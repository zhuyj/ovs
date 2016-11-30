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
del_ufid_tc_mapping(ovs_u128 *ufid)
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
get_ufid_tc_mapping(ovs_u128 *ufid, int *prio, struct netdev **netdev)
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
add_ufid_tc_mapping(ovs_u128 *ufid, int prio, int handle, struct netdev *netdev)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    bool replace = del_ufid_tc_mapping(ufid);
    struct ufid_to_tc_data *new_data = malloc(sizeof *new_data);

    new_data->ufid = *ufid;
    new_data->prio = prio;
    new_data->handle = handle;
    new_data->netdev = netdev_ref(netdev);

    ovs_mutex_lock(&ufid_lock);
    hmap_insert(&ufid_to_tc, &new_data->node, hash);
    ovs_mutex_unlock(&ufid_lock);

    return replace;
}

int
netdev_tc_flow_flush(struct netdev *netdev)
{
    return tc_flush_flower(netdev_get_ifindex(netdev));
}

struct netdev_flow_dump *
netdev_tc_flow_dump_create(struct netdev *netdev)
{
    struct netdev_flow_dump *dump = malloc(sizeof *dump);

    memset(dump, 0, sizeof(*dump));
    dump->netdev = netdev;
    return dump;
}

int
netdev_tc_flow_dump_destroy(struct netdev_flow_dump *dump)
{
    free(dump);

    return 0;
}

bool
netdev_tc_flow_dump_next(struct netdev_flow_dump *dump OVS_UNUSED,
                            struct match *match OVS_UNUSED,
                            struct nlattr **actions OVS_UNUSED,
                            struct dpif_flow_stats *stats OVS_UNUSED,
                            ovs_u128 *ufid OVS_UNUSED,
                            struct ofpbuf *rbuffer OVS_UNUSED,
                            struct ofpbuf *wbuffer OVS_UNUSED)
{
    return false;
}

int
netdev_tc_flow_put(struct netdev *netdev OVS_UNUSED,
                      struct match *match OVS_UNUSED,
                      struct nlattr *actions OVS_UNUSED,
                      size_t actions_len OVS_UNUSED,
                      struct dpif_flow_stats *stats OVS_UNUSED,
                      ovs_u128 *ufid OVS_UNUSED)
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
                      struct dpif_flow_stats *stats OVS_UNUSED,
                      ovs_u128 *ufid OVS_UNUSED)
{
    return EOPNOTSUPP;
}

int
netdev_tc_init_flow_api(struct netdev *netdev OVS_UNUSED)
{
    return 0;
}

