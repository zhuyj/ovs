
#include <config.h>

#include "dpif-netlink.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <linux/types.h>
#include <linux/pkt_sched.h>
#include <poll.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bitmap.h"
#include "dpif-provider.h"
#include "dynamic-string.h"
#include "flow.h"
#include "fat-rwlock.h"
#include "netdev.h"
#include "netdev-linux.h"
#include "netdev-vport.h"
#include "netlink-conntrack.h"
#include "netlink-notifier.h"
#include "netlink-socket.h"
#include "netlink.h"
#include "odp-util.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "random.h"
#include "shash.h"
#include "sset.h"
#include "timeval.h"
#include "unaligned.h"
#include "util.h"
#include "openvswitch/vlog.h"
#include "netdev-provider.h"
#include "dpif-hw-acc.h"
#include "tc.h"
#include "hw-offload-policy.h"

VLOG_DEFINE_THIS_MODULE(dpif_hw_acc);

static char *
printufid(const ovs_u128 * ovs_ufid)
{
    static char ufid[64];

    if (ovs_ufid)
        sprintf(ufid, "%x%x%x%x", ovs_ufid->u32[0], ovs_ufid->u32[1],
                ovs_ufid->u32[2], ovs_ufid->u32[3]);
    else
        sprintf(ufid, "(missing_ufid)");
    return ufid;
}

static inline size_t
hash_ufid(const ovs_u128 * ovs_ufid)
{
    return hash_words64((const uint64_t *) ovs_ufid,
                        sizeof *ovs_ufid / sizeof (uint64_t), 0);
}

static inline size_t
hash_port(odp_port_t port)
{
    return hash_int((int) port, 0);
}

static inline size_t
hash_handle_prio_port(int handle, uint16_t prio, odp_port_t port)
{
    /* TODO: fix utint cast */
    return hash_int((uint32_t) prio, hash_int(handle, hash_port(port)));
}

static struct netdev *
port_find(struct dpif_hw_acc *dpif, odp_port_t port)
{
    struct port_netdev_hash_data *data;
    size_t hash = hash_port(port);
    struct netdev *res = 0;

    ovs_mutex_lock(&dpif->hash_mutex);
    HMAP_FOR_EACH_WITH_HASH(data, node, hash, &dpif->port_to_netdev) {
        if (data->port == port)
            break;
    }
    if (data) {
        res = data->netdev;
        VLOG_DBG
            ("found port mapping: port number %d -> port name %s (pointer: %p)\n",
             port, res->name, res);
    }
    ovs_mutex_unlock(&dpif->hash_mutex);

    return res;
}

static int
port_del_name(struct dpif_hw_acc *dpif, char *name)
{
    struct port_netdev_hash_data *data;

    ovs_mutex_lock(&dpif->hash_mutex);
    HMAP_FOR_EACH(data, node, &dpif->port_to_netdev) {
        if (!strcmp(data->netdev->name, name))
            break;
    }
    if (data)
        hmap_remove(&dpif->port_to_netdev, &data->node);
    ovs_mutex_unlock(&dpif->hash_mutex);

    free(data);
    return data ? 1 : 0;
}

static int
port_del(struct dpif_hw_acc *dpif, odp_port_t port)
{
    struct port_netdev_hash_data *data;
    size_t hash = hash_port(port);

    ovs_mutex_lock(&dpif->hash_mutex);
    HMAP_FOR_EACH_WITH_HASH(data, node, hash, &dpif->port_to_netdev) {
        if (data->port == port)
            break;
    }
    if (data)
        hmap_remove(&dpif->port_to_netdev, &data->node);
    ovs_mutex_unlock(&dpif->hash_mutex);

    free(data);
    return data ? 1 : 0;
}

static int
port_add(struct dpif_hw_acc *dpif, odp_port_t port, struct netdev *netdev)
{
    struct port_netdev_hash_data *data;
    size_t hash = hash_port(port);
    int ret = 0;

    if (!netdev || !netdev->name || !port)
        return -1;

    if (netdev->netdev_class == &netdev_internal_class) {
        if (!strcmp(netdev->name, "skip_hw")) {
            tc_set_skip_hw(true);
        }
        return -1;
    }
    if (port_del(dpif, port) || port_del_name(dpif, netdev->name)) {
        VLOG_DBG
            ("%s %d %s (%p)  port number %d name: %s, deleted to be replaced\n",
             __FILE__, __LINE__, __func__, dpif, port, netdev->name);
        ret = 1;
    }

    data = malloc(sizeof (struct port_netdev_hash_data));
    data->netdev = netdev;
    data->port = port;

    VLOG_DBG
        ("%s %d %s (%p): adding new port mapping: %d -> netdev %p name: %s, type: %s, ifindex: %d, hash: %lu\n",
         __FILE__, __LINE__, __func__, dpif, port, netdev, netdev->name,
         netdev->netdev_class->type, netdev_get_ifindex(netdev), hash);
    ovs_mutex_lock(&dpif->hash_mutex);
    hmap_insert(&dpif->port_to_netdev, &data->node, hash);
    ovs_mutex_unlock(&dpif->hash_mutex);
    return ret;
}

static int
delhandle(struct dpif_hw_acc *dpif, const ovs_u128 * ovs_ufid)
{
    struct ufid_handle_hash_data *data;
    size_t hash;

    if (!ovs_ufid) {
        VLOG_ERR("%s %d %s (%p) can't delete missing ufid\n", __FILE__,
                 __LINE__, __func__, dpif);
        return 0;
    }
    hash = hash_ufid(ovs_ufid);

    VLOG_DBG("%s %d %s (%p): removing %s\n", __FILE__, __LINE__, __func__,
             dpif, printufid(ovs_ufid));

    ovs_mutex_lock(&dpif->hash_mutex);
    HMAP_FOR_EACH_WITH_HASH(data, node_ufid, hash, &dpif->ufid_to_handle) {
        if (!memcmp(&data->ovs_ufid, ovs_ufid, sizeof (*ovs_ufid)))
            break;
    }
    if (data) {
        VLOG_DBG("%s %d %s (%p)  ufid %s found! handle: %d, removing it\n",
                 __FILE__, __LINE__, __func__, dpif, printufid(ovs_ufid),
                 data->handle);
        hmap_remove(&dpif->ufid_to_handle, &data->node_ufid);
        hmap_remove(&dpif->handle_to_ufid, &data->node_handle);
        free(data);
    }
    ovs_mutex_unlock(&dpif->hash_mutex);
    return data ? 1 : 0;
}

static int
puthandle(struct dpif_hw_acc *dpif, const ovs_u128 * ovs_ufid,
          struct netdev *in, odp_port_t port, int handle, uint16_t prio)
{
    int ret = 0;
    size_t hash_to_ufid = hash_handle_prio_port(handle, prio, port);

    if (!ovs_ufid) {
        VLOG_ERR("%s %d %s (%p) missing UFID!\n", __FILE__, __LINE__, __func__,
                 dpif);
        return 0;
    }

    if (delhandle(dpif, ovs_ufid))
        ret = 1;

    struct ufid_handle_hash_data *data =
        malloc(sizeof (struct ufid_handle_hash_data));
    data->ovs_ufid = *ovs_ufid;
    data->handle = handle;
    data->netdev = in;
    data->port = port;
    data->prio = prio;

    ovs_mutex_lock(&dpif->hash_mutex);
    hmap_insert(&dpif->ufid_to_handle, &data->node_ufid, hash_ufid(ovs_ufid));
    hmap_insert(&dpif->handle_to_ufid, &data->node_handle, hash_to_ufid);
    VLOG_DBG
        ("%s %d %s (%p) added mapping %s <-> (handle: %d, prio: %d, port: %d, indev: %p)\n",
         __FILE__, __LINE__, __func__, dpif, printufid(ovs_ufid), handle,
         prio, port, in);
    ovs_mutex_unlock(&dpif->hash_mutex);
    return ret;
}

static ovs_u128 *
findufid(struct dpif_hw_acc *dpif, odp_port_t port, int handle,
         uint16_t prio)
{
    struct ufid_handle_hash_data *data;
    size_t hash = hash_handle_prio_port(handle, prio, port);

    VLOG_DBG
        ("%s %d %s (%p) finding ufid of (handle: %d,  prio: %d,  port: %d), hash: %lu\n",
         __FILE__, __LINE__, __func__, dpif, handle, prio, port, hash);

    ovs_mutex_lock(&dpif->hash_mutex);
    HMAP_FOR_EACH_WITH_HASH(data, node_handle, hash, &dpif->handle_to_ufid) {
        if (data->handle == handle && data->port == port
            && data->prio == prio)
            break;
    }
    ovs_mutex_unlock(&dpif->hash_mutex);

    return data ? &data->ovs_ufid : 0;
}

static int
gethandle(struct dpif_hw_acc *dpif, const ovs_u128 * ovs_ufid,
          struct netdev **in, uint16_t *prio, const char *func, int print)
{
    struct ufid_handle_hash_data *data;
    int handle = 0;
    size_t hash = 0;

    if (in)
        *in = 0;

    if (!ovs_ufid) {
        VLOG_DBG("%s %d %s (%p) called by %s without a ufid.\n", __FILE__,
                 __LINE__, __func__, dpif, func);
        return 0;
    } else
        hash = hash_ufid(ovs_ufid);

    if (print)
        VLOG_DBG("%s %d %s (%p) called by %s to find ufid %s\n", __FILE__,
                 __LINE__, __func__, dpif, func, printufid(ovs_ufid));

    ovs_mutex_lock(&dpif->hash_mutex);
    HMAP_FOR_EACH_WITH_HASH(data, node_ufid, hash, &dpif->ufid_to_handle) {
        if (!memcmp(&data->ovs_ufid, ovs_ufid, sizeof (*ovs_ufid)))
            break;
    }
    ovs_mutex_unlock(&dpif->hash_mutex);

    if (data && (!data->handle || !data->netdev || !data->prio)) {
        VLOG_ERR
            ("mising handle/dev/prio for ufid: %s, handle: %d, netdev: %p, prio: %d\n",
             printufid(ovs_ufid), data->handle, data->netdev, data->prio);
        return 0;
    }
    handle = data ? data->handle : 0;
    if (in)
        *in = data ? data->netdev : 0;
    if (prio)
        *prio = data ? data->prio : 0;
    if (print && handle)
        VLOG_DBG("found ufid: %s, handle: %d, prio: %d, netdev: %p\n",
                 printufid(ovs_ufid), handle, data->prio, data->netdev);
    return handle;
}

static int
get_ovs_port(struct dpif_hw_acc *dpif, int ifindex)
{
    struct port_netdev_hash_data *data;

    HMAP_FOR_EACH(data, node, &dpif->port_to_netdev) {
        if (netdev_get_ifindex(data->netdev) == ifindex) {
            return data->port;
        }
    }
    return -1;
}

static struct dpif_hw_acc *
dpif_hw_acc_cast(const struct dpif *dpif)
{
    dpif_assert_class(dpif, &dpif_hw_acc_class);
    return CONTAINER_OF(dpif, struct dpif_hw_acc, dpif);
}

static int
initmaps(struct dpif_hw_acc *dpif)
{
    hmap_init(&dpif->port_to_netdev);
    hmap_init(&dpif->ufid_to_handle);
    hmap_init(&dpif->handle_to_ufid);
    ovs_mutex_init(&dpif->hash_mutex);
    return 0;
}

static int
dpif_hw_acc_open(const struct dpif_class *class OVS_UNUSED,
                     const char *name, bool create, struct dpif **dpifp)
{
    struct dpif_hw_acc *dpif;
    struct dpif *lp_dpif_netlink;
    struct netdev *netdev;
    struct dpif_port dpif_port;
    struct dpif_port_dump dump;
    int error = 0;

    VLOG_DBG("%s %d %s: parameters name %s, create: %s\n", __FILE__, __LINE__,
             __func__, name, (create ? "yes" : "no"));
    if (create) {
        if ((error = dpif_create(name, "system", &lp_dpif_netlink))) {
            return error;
        }
    } else {
        if ((error = dpif_open(name, "system", &lp_dpif_netlink))) {
            return error;
        }
    }
    dpif = xzalloc(sizeof *dpif);

    initmaps(dpif);

    *CONST_CAST(const char **, &dpif->name) = xstrdup(name);
    uint16_t netflow_id = hash_string(dpif->name, 0);

    dpif->lp_dpif_netlink = lp_dpif_netlink;

    dpif_init(&dpif->dpif, &dpif_hw_acc_class, dpif->name, netflow_id >> 8,
              netflow_id);

    *dpifp = &dpif->dpif;

    return 0;
}

static void
dpif_hw_acc_close(struct dpif *dpif_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->close(dpif->lp_dpif_netlink);
}

static int
dpif_hw_acc_destroy(struct dpif *dpif_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->destroy(dpif->lp_dpif_netlink);
}

static bool
dpif_hw_acc_run(struct dpif *dpif_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->run(dpif->lp_dpif_netlink);
}

static int
dpif_hw_acc_get_stats(const struct dpif *dpif_,
                          struct dpif_dp_stats *stats)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->get_stats(dpif->lp_dpif_netlink,
                                                        stats);
}

static int
dpif_hw_acc_port_add(struct dpif *dpif_, struct netdev *netdev,
                         odp_port_t * port_nop)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->port_add(dpif->lp_dpif_netlink,
                                                       netdev, port_nop);
}

static int
dpif_hw_acc_port_del(struct dpif *dpif_, odp_port_t port_no)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->port_del(dpif->lp_dpif_netlink,
                                                       port_no);
}

static int
dpif_hw_acc_port_query_by_number(const struct dpif *dpif_,
                                     odp_port_t port_no,
                                     struct dpif_port *dpif_port)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        port_query_by_number(dpif->lp_dpif_netlink, port_no, dpif_port);
}

static int
dpif_hw_acc_port_query_by_name(const struct dpif *dpif_,
                                   const char *devname,
                                   struct dpif_port *dpif_port)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        port_query_by_name(dpif->lp_dpif_netlink, devname, dpif_port);
}

static uint32_t
dpif_hw_acc_port_get_pid(const struct dpif *dpif_, odp_port_t port_no,
                             uint32_t hash)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        port_get_pid(dpif->lp_dpif_netlink, port_no, hash);
}

static int
dpif_hw_acc_port_dump_start(const struct dpif *dpif_, void **statep)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        port_dump_start(dpif->lp_dpif_netlink, statep);
}

static int
dpif_hw_acc_port_dump_next(const struct dpif *dpif_, void *state_,
                               struct dpif_port *dpif_port)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        port_dump_next(dpif->lp_dpif_netlink, state_, dpif_port);
}

static int
dpif_hw_acc_port_dump_done(const struct dpif *dpif_ OVS_UNUSED,
                               void *state_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        port_dump_done(dpif->lp_dpif_netlink, state_);
}

static int
dpif_hw_acc_port_poll(const struct dpif *dpif_, char **devnamep)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->port_poll(dpif->lp_dpif_netlink,
                                                        devnamep);
}

static void
dpif_hw_acc_port_poll_wait(const struct dpif *dpif_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        port_poll_wait(dpif->lp_dpif_netlink);
}

static int
dpif_hw_acc_flow_flush(struct dpif *dpif_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        flow_flush(dpif->lp_dpif_netlink);
}

static struct dpif_flow_dump *
dpif_hw_acc_flow_dump_create(const struct dpif *dpif_, bool terse)
{
    struct dpif_flow_dump *dump;
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    dump =
        dpif->lp_dpif_netlink->dpif_class->
        flow_dump_create(dpif->lp_dpif_netlink, terse);
    dump->dpif = CONST_CAST(struct dpif *, dpif_);

    return dump;

}

static int
dpif_hw_acc_flow_dump_destroy(struct dpif_flow_dump *dump_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dump_->dpif);

    dump_->dpif = dpif->lp_dpif_netlink;
    return dpif->lp_dpif_netlink->dpif_class->flow_dump_destroy(dump_);
}

static struct dpif_flow_dump_thread *
dpif_hw_acc_flow_dump_thread_create(struct dpif_flow_dump *dump_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dump_->dpif);

    return dpif->lp_dpif_netlink->dpif_class->flow_dump_thread_create(dump_);

}

static void
dpif_hw_acc_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(thread_->dpif);

    thread_->dpif = dpif->lp_dpif_netlink;
    return dpif->lp_dpif_netlink->
        dpif_class->flow_dump_thread_destroy(thread_);
}

static int
dpif_hw_acc_flow_dump_next(struct dpif_flow_dump_thread *thread_,
                               struct dpif_flow *flows, int max_flows)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(thread_->dpif);

    thread_->dpif = dpif->lp_dpif_netlink;
    return dpif->lp_dpif_netlink->dpif_class->flow_dump_next(thread_, flows,
                                                             max_flows);
}

static void
dpif_hw_acc_operate(struct dpif *dpif_, struct dpif_op **ops, size_t n_ops)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->operate(dpif->lp_dpif_netlink,
                                                      ops, n_ops);
}

static int
dpif_hw_acc_recv_set(struct dpif *dpif_, bool enable)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->recv_set(dpif->lp_dpif_netlink,
                                                       enable);
}

static int
dpif_hw_acc_handlers_set(struct dpif *dpif_, uint32_t n_handlers)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        handlers_set(dpif->lp_dpif_netlink, n_handlers);
}

static int
dpif_hw_acc_queue_to_priority(const struct dpif *dpif_,
                                  uint32_t queue_id, uint32_t * priority)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        queue_to_priority(dpif->lp_dpif_netlink, queue_id, priority);
}

static int
dpif_hw_acc_recv(struct dpif *dpif_, uint32_t handler_id,
                     struct dpif_upcall *upcall, struct ofpbuf *buf)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->recv(dpif->lp_dpif_netlink,
                                                   handler_id, upcall, buf);

}

static void
dpif_hw_acc_recv_wait(struct dpif *dpif_, uint32_t handler_id)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->recv_wait(dpif->lp_dpif_netlink,
                                                        handler_id);
}

static void
dpif_hw_acc_recv_purge(struct dpif *dpif_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        recv_purge(dpif->lp_dpif_netlink);
}

static int
dpif_hw_acc_ct_dump_start(struct dpif *dpif_,
                              struct ct_dpif_dump_state **dump_,
                              const uint16_t * zone)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        ct_dump_start(dpif->lp_dpif_netlink, dump_, zone);
}

static int
dpif_hw_acc_ct_dump_next(struct dpif *dpif_,
                             struct ct_dpif_dump_state *dump_,
                             struct ct_dpif_entry *entry)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        ct_dump_next(dpif->lp_dpif_netlink, dump_, entry);
}

static int
dpif_hw_acc_ct_dump_done(struct dpif *dpif_,
                             struct ct_dpif_dump_state *dump_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        ct_dump_done(dpif->lp_dpif_netlink, dump_);
}

static int
dpif_hw_acc_ct_flush(struct dpif *dpif_, const uint16_t * zone)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->ct_flush(dpif->lp_dpif_netlink,
                                                       zone);
}

const struct dpif_class dpif_hw_acc_class = {
    "hw_netlink",
    NULL,                       /* init */
    NULL,
    NULL,
    dpif_hw_acc_open,
    dpif_hw_acc_close,
    dpif_hw_acc_destroy,
    dpif_hw_acc_run,
    NULL,                       /* wait */
    dpif_hw_acc_get_stats,
    dpif_hw_acc_port_add,
    dpif_hw_acc_port_del,
    dpif_hw_acc_port_query_by_number,
    dpif_hw_acc_port_query_by_name,
    dpif_hw_acc_port_get_pid,
    dpif_hw_acc_port_dump_start,
    dpif_hw_acc_port_dump_next,
    dpif_hw_acc_port_dump_done,
    dpif_hw_acc_port_poll,
    dpif_hw_acc_port_poll_wait,
    dpif_hw_acc_flow_flush,
    dpif_hw_acc_flow_dump_create,
    dpif_hw_acc_flow_dump_destroy,
    dpif_hw_acc_flow_dump_thread_create,
    dpif_hw_acc_flow_dump_thread_destroy,
    dpif_hw_acc_flow_dump_next,
    dpif_hw_acc_operate,
    dpif_hw_acc_recv_set,
    dpif_hw_acc_handlers_set,
    NULL,                       /* poll_thread_set */
    dpif_hw_acc_queue_to_priority,
    dpif_hw_acc_recv,
    dpif_hw_acc_recv_wait,
    dpif_hw_acc_recv_purge,
    NULL,                       /* register_dp_purge_cb */
    NULL,                       /* register_upcall_cb */
    NULL,                       /* enable_upcall */
    NULL,                       /* disable_upcall */
    NULL,                       /* get_datapath_version */
#ifdef __linux__
    dpif_hw_acc_ct_dump_start,
    dpif_hw_acc_ct_dump_next,
    dpif_hw_acc_ct_dump_done,
    dpif_hw_acc_ct_flush,
#else
    NULL,                       /* ct_dump_start */
    NULL,                       /* ct_dump_next */
    NULL,                       /* ct_dump_done */
    NULL,                       /* ct_flush */
#endif
};
