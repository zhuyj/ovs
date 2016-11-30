/*
 * Copyright (c) 2016 Mellanox Technologies, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "netdev-tc-offloads.h"

#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <linux/filter.h>
#include <linux/gen_stats.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/types.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_packet.h>
#include <net/route.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "coverage.h"
#include "dp-packet.h"
#include "dpif-netlink.h"
#include "dpif-netdev.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "netlink-notifier.h"
#include "netlink-socket.h"
#include "netlink.h"
#include "openvswitch/ofpbuf.h"
#include "openflow/openflow.h"
#include "ovs-atomic.h"
#include "packets.h"
#include "poll-loop.h"
#include "rtnetlink.h"
#include "openvswitch/shash.h"
#include "netdev-provider.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"
#include "tc.h"

VLOG_DEFINE_THIS_MODULE(netdev_tc_offloads);

static struct hmap ufid_to_tc = HMAP_INITIALIZER(&ufid_to_tc);
static struct ovs_mutex ufid_lock = OVS_MUTEX_INITIALIZER;

struct ufid_to_tc_data {
    struct hmap_node node;
    ovs_u128 ufid;
    uint16_t prio;
    uint32_t handle;
    struct netdev *netdev;
};

static bool
del_ufid_tc_mapping(const ovs_u128 *ufid)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_tc_data *data;

    ovs_mutex_lock(&ufid_lock);
    HMAP_FOR_EACH_WITH_HASH(data, node, hash, &ufid_to_tc) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            break;
        }
    }
    if (data) {
        hmap_remove(&ufid_to_tc, &data->node);
        ovs_mutex_unlock(&ufid_lock);
        netdev_close(data->netdev);
        free(data);
        return true;
    }
    ovs_mutex_unlock(&ufid_lock);
    return false;
}

static ovs_u128 *
find_ufid(int prio, int handle, struct netdev *netdev)
{
    int ifindex = netdev_get_ifindex(netdev);
    struct ufid_to_tc_data *data;

    ovs_mutex_lock(&ufid_lock);
    HMAP_FOR_EACH(data, node, &ufid_to_tc) {
        if (data->prio == prio && data->handle == handle
            && netdev_get_ifindex(data->netdev) == ifindex) {
            break;
        }
    }
    ovs_mutex_unlock(&ufid_lock);
    if (data) {
        return &data->ufid;
    }
    return NULL;
}

static int
get_ufid_tc_mapping(const ovs_u128 *ufid, int *prio, struct netdev **netdev)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_tc_data *data;

    ovs_mutex_lock(&ufid_lock);
    HMAP_FOR_EACH_WITH_HASH(data, node, hash, &ufid_to_tc) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            break;
        }
    }
    ovs_mutex_unlock(&ufid_lock);
    if (data) {
        if (prio) {
            *prio = data->prio;
        }
        if (netdev) {
            *netdev = netdev_ref(data->netdev);
        }
        return data->handle;
    }
    return 0;
}

static bool
add_ufid_tc_mapping(const ovs_u128 *ufid, int prio, int handle,
                    struct netdev *netdev)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    bool replace = del_ufid_tc_mapping(ufid);
    struct ufid_to_tc_data *new_data = xzalloc(sizeof *new_data);

    new_data->ufid = *ufid;
    new_data->prio = prio;
    new_data->handle = handle;
    new_data->netdev = netdev_ref(netdev);

    ovs_mutex_lock(&ufid_lock);
    hmap_insert(&ufid_to_tc, &new_data->node, hash);
    ovs_mutex_unlock(&ufid_lock);

    return replace;
}

struct prio_map_data {
    struct hmap_node node;
    struct tc_flower_key mask;
    ovs_be16 protocol;
    uint16_t prio;
};

static uint16_t
get_prio_for_tc_flower(struct tc_flower *flower)
{
    static struct hmap prios = HMAP_INITIALIZER(&prios);
    static struct ovs_mutex prios_lock = OVS_MUTEX_INITIALIZER;
    static int last_prio = 0;
    size_t key_len = sizeof(struct tc_flower_key);
    size_t hash = hash_bytes(&flower->mask, key_len,
                             (OVS_FORCE uint32_t) flower->key.eth_type);
    struct prio_map_data *data;
    struct prio_map_data *new_data;

    ovs_mutex_lock(&prios_lock);
    HMAP_FOR_EACH_WITH_HASH(data, node, hash, &prios) {
        if (!memcmp(&flower->mask, &data->mask, key_len)
            && data->protocol == flower->key.eth_type) {
            ovs_mutex_unlock(&prios_lock);
            return data->prio;
        }
    }

    new_data = xzalloc(sizeof *new_data);
    memcpy(&new_data->mask, &flower->mask, key_len);
    new_data->prio = ++last_prio;
    new_data->protocol = flower->key.eth_type;
    hmap_insert(&prios, &new_data->node, hash);
    ovs_mutex_unlock(&prios_lock);

    return new_data->prio;
}

int
netdev_tc_flow_flush(struct netdev *netdev)
{
    int ifindex = netdev_get_ifindex(netdev);

    if (ifindex < 0) {
        VLOG_ERR_RL(&rl_err, "failed to get ifindex for %s: %s",
                    netdev_get_name(netdev), ovs_strerror(-ifindex));
        return -ifindex;
    }

    return tc_flush(ifindex);
}

int
netdev_tc_flow_dump_create(struct netdev *netdev,
                           struct netdev_flow_dump **dump_out)
{
    struct netdev_flow_dump *dump;
    int ifindex;

    ifindex = netdev_get_ifindex(netdev);
    if (ifindex < 0) {
        VLOG_ERR_RL(&rl_err, "failed to get ifindex for %s: %s",
                    netdev_get_name(netdev), ovs_strerror(-ifindex));
        return -ifindex;
    }

    dump = xzalloc(sizeof *dump);
    dump->nl_dump = xzalloc(sizeof *dump->nl_dump);
    dump->netdev = netdev_ref(netdev);
    tc_dump_flower_start(ifindex, dump->nl_dump);

    *dump_out = dump;

    return 0;
}

int
netdev_tc_flow_dump_destroy(struct netdev_flow_dump *dump)
{
    nl_dump_done(dump->nl_dump);
    netdev_close(dump->netdev);
    free(dump->nl_dump);
    free(dump);
    return 0;
}

static int
parse_tc_flower_to_match(struct tc_flower *flower,
                         struct match *match,
                         struct nlattr **actions,
                         struct dpif_flow_stats *stats,
                         struct ofpbuf *buf) {
    size_t act_off;
    struct tc_flower_key *key = &flower->key;
    struct tc_flower_key *mask = &flower->mask;
    odp_port_t outport = 0;

    if (flower->ifindex_out) {
        outport = netdev_hmap_port_get_byifidx(flower->ifindex_out);
        if (!outport) {
            return ENOENT;
        }
    }

    match_init_catchall(match);
    match_set_dl_type(match, key->eth_type);
    match_set_dl_src_masked(match, key->src_mac, mask->src_mac);
    match_set_dl_dst_masked(match, key->dst_mac, mask->dst_mac);
    if (key->vlan_id || key->vlan_prio) {
        match_set_dl_vlan(match, htons(key->vlan_id));
        match_set_dl_vlan_pcp(match, key->vlan_prio);
        match_set_dl_type(match, key->encap_eth_type);
    }

    if (key->ip_proto &&
        (key->eth_type == htons(ETH_P_IP)
         || key->eth_type == htons(ETH_P_IPV6))) {
        match_set_nw_proto(match, key->ip_proto);
    }
    match_set_nw_src_masked(match, key->ipv4.ipv4_src, mask->ipv4.ipv4_src);
    match_set_nw_dst_masked(match, key->ipv4.ipv4_dst, mask->ipv4.ipv4_dst);

    match_set_tp_dst_masked(match, key->dst_port, mask->dst_port);
    match_set_tp_src_masked(match, key->src_port, mask->src_port);

    if (flower->tunnel.tunnel) {
        match_set_tun_id(match, flower->tunnel.id);
        match_set_tun_src(match, flower->tunnel.ipv4_src);
        match_set_tun_dst(match, flower->tunnel.ipv4_dst);
        match_set_tp_dst(match, flower->tunnel.tp_dst);
    }

    act_off = nl_msg_start_nested(buf, OVS_FLOW_ATTR_ACTIONS);
    {
        if (flower->vlan_pop) {
            nl_msg_put_flag(buf, OVS_ACTION_ATTR_POP_VLAN);
        }

        if (flower->vlan_push_id || flower->vlan_push_prio) {
            struct ovs_action_push_vlan *push;
            push = nl_msg_put_unspec_zero(buf, OVS_ACTION_ATTR_PUSH_VLAN,
                                          sizeof *push);

            push->vlan_tpid = htons(ETH_TYPE_VLAN);
            push->vlan_tci = htons(flower->vlan_push_id
                                   | (flower->vlan_push_prio << 13)
                                   | VLAN_CFI);
        }

        if (flower->ifindex_out > 0) {
            nl_msg_put_u32(buf, OVS_ACTION_ATTR_OUTPUT, odp_to_u32(outport));
        }

        if (flower->set.set) {
            size_t set_offset = nl_msg_start_nested(buf, OVS_ACTION_ATTR_SET);
            size_t tunnel_offset =
                nl_msg_start_nested(buf, OVS_KEY_ATTR_TUNNEL);

            nl_msg_put_be64(buf, OVS_TUNNEL_KEY_ATTR_ID, flower->set.id);
            nl_msg_put_be32(buf, OVS_TUNNEL_KEY_ATTR_IPV4_SRC,
                            flower->set.ipv4_src);
            nl_msg_put_be32(buf, OVS_TUNNEL_KEY_ATTR_IPV4_DST,
                            flower->set.ipv4_dst);
            nl_msg_put_be16(buf, OVS_TUNNEL_KEY_ATTR_TP_DST,
                            flower->set.tp_dst);

            nl_msg_end_nested(buf, tunnel_offset);
            nl_msg_end_nested(buf, set_offset);
        }
    }
    nl_msg_end_nested(buf, act_off);

    *actions = ofpbuf_at_assert(buf, act_off, sizeof(struct nlattr));

    if (stats) {
        memset(stats, 0, sizeof *stats);
        stats->n_packets = get_32aligned_u64(&flower->stats.n_packets);
        stats->n_bytes = get_32aligned_u64(&flower->stats.n_bytes);
        stats->used = flower->lastused;
    }

    return 0;
}

bool
netdev_tc_flow_dump_next(struct netdev_flow_dump *dump,
                            struct match *match,
                            struct nlattr **actions,
                            struct dpif_flow_stats *stats,
                            ovs_u128 *ufid,
                            struct ofpbuf *rbuffer,
                            struct ofpbuf *wbuffer)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
    struct ofpbuf nl_flow;

    for (;;) {
        if (nl_dump_next(dump->nl_dump, &nl_flow, rbuffer)) {
            struct tc_flower flower;
            ovs_u128 *uf;

            if (parse_netlink_to_tc_flower(&nl_flow, &flower)) {
                continue;
            }

            if (parse_tc_flower_to_match(&flower, match, actions, stats,
                                         wbuffer)) {
                continue;
            }

            uf = find_ufid(flower.prio, flower.handle, dump->netdev);
            if (!uf) {
                VLOG_DBG_RL(&rl, "unmatched flow (dev %s prio %d handle %d)",
                            netdev_get_name(dump->netdev),
                            flower.prio, flower.handle);
                dpif_flow_hash(NULL, &match->flow, sizeof match->flow, ufid);
                add_ufid_tc_mapping(ufid, flower.prio, flower.handle,
                                    dump->netdev);
            } else {
                *ufid = *uf;
            }

            match->wc.masks.in_port.odp_port = u32_to_odp(UINT32_MAX);
            match->flow.in_port.odp_port = dump->port;

            return true;
        }
        break;
    }
    return false;
}

int
netdev_tc_flow_put(struct netdev *netdev OVS_UNUSED,
                      struct match *match OVS_UNUSED,
                      struct nlattr *actions OVS_UNUSED,
                      size_t actions_len OVS_UNUSED,
                      struct dpif_flow_stats *stats OVS_UNUSED,
                      ovs_u128 *ufid OVS_UNUSED,
                      struct offload_info *info OVS_UNUSED)
{
    return EOPNOTSUPP;
}

int
netdev_tc_flow_get(struct netdev *netdev OVS_UNUSED,
                      struct match *match OVS_UNUSED,
                      struct nlattr **actions OVS_UNUSED,
                      struct dpif_flow_stats *stats OVS_UNUSED,
                      ovs_u128 *ufid OVS_UNUSED,
                      struct ofpbuf *buf OVS_UNUSED)
{
    return EOPNOTSUPP;
}

int
netdev_tc_flow_del(struct netdev *netdev OVS_UNUSED,
                   struct dpif_flow_stats *stats,
                   const ovs_u128 *ufid)
{
    return EOPNOTSUPP;
}

int
netdev_tc_init_flow_api(struct netdev *netdev OVS_UNUSED)
{
    return 0;
}

