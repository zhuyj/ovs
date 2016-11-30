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

struct prio_map_data {
    struct hmap_node node;
    struct tc_flow_key mask;
    uint16_t protocol;
    uint16_t prio;
};

static uint16_t
get_prio_for_tc_flow(struct tc_flow *tc_flow)
{
    static struct hmap prios = HMAP_INITIALIZER(&prios);
    static struct ovs_mutex prios_lock = OVS_MUTEX_INITIALIZER;
    static int last_prio = 0;
    size_t key_len = sizeof(struct tc_flow_key);
    size_t hash = hash_bytes(&tc_flow->mask, key_len, tc_flow->key.eth_type);
    struct prio_map_data *data;
    struct prio_map_data *new_data;

    ovs_mutex_lock(&prios_lock);
    HMAP_FOR_EACH_WITH_HASH(data, node, hash, &prios) {
        if (!memcmp(&tc_flow->mask, &data->mask, key_len)
            && data->protocol == tc_flow->key.eth_type) {
            ovs_mutex_unlock(&prios_lock);
            return data->prio;
        }
    }

    new_data  = malloc(sizeof(*new_data));
    memcpy(&new_data->mask, &tc_flow->mask, key_len);
    new_data->prio = ++last_prio;
    new_data->protocol = tc_flow->key.eth_type;
    hmap_insert(&prios, &new_data->node, hash);
    ovs_mutex_unlock(&prios_lock);

    return new_data->prio;
}

int
netdev_tc_flow_flush(struct netdev *netdev)
{
    return tc_flush_flower(netdev_get_ifindex(netdev));
}

struct netdev_flow_dump *
netdev_tc_flow_dump_create(struct netdev *netdev)
{
    struct netdev_flow_dump *dump = malloc(sizeof(*dump));

    memset(dump, 0, sizeof(*dump));
    dump->nl_dump = malloc(sizeof *dump->nl_dump);
    dump->netdev = netdev_ref(netdev);
    tc_dump_flower_start(netdev_get_ifindex(netdev), dump->nl_dump);
    return dump;
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
parse_tc_flow_to_match(struct tc_flow *tc_flow,
                       struct match *match,
                       struct nlattr **actions,
                       struct dpif_flow_stats *stats,
                       struct ofpbuf *buf) {
    size_t act_off;

    match_init_catchall(match);
    match_set_dl_type(match, tc_flow->key.eth_type);
    match_set_dl_src_masked(match, tc_flow->key.src_mac, tc_flow->mask.src_mac);
    match_set_dl_dst_masked(match, tc_flow->key.dst_mac, tc_flow->mask.dst_mac);
    if (tc_flow->key.vlan_id || tc_flow->key.vlan_prio) {
        match_set_dl_vlan(match, ntohs(tc_flow->key.vlan_id));
        match_set_dl_vlan_pcp(match, ntohs(tc_flow->key.vlan_prio));
        match_set_dl_type(match, tc_flow->key.encap_eth_type);
    }

    if (tc_flow->key.ip_proto &&
        (tc_flow->key.eth_type == htons(ETH_P_IP) ||
         tc_flow->key.eth_type == htons(ETH_P_IPV6))) {
        match_set_nw_proto(match, tc_flow->key.ip_proto);
    }
    match_set_nw_src_masked(match, tc_flow->key.ipv4.ipv4_src, tc_flow->mask.ipv4.ipv4_src);
    match_set_nw_dst_masked(match, tc_flow->key.ipv4.ipv4_dst, tc_flow->mask.ipv4.ipv4_dst);

    match_set_tp_dst_masked(match, tc_flow->key.dst_port, tc_flow->mask.dst_port);
    match_set_tp_src_masked(match, tc_flow->key.src_port, tc_flow->mask.src_port);

    if (tc_flow->tunnel.tunnel) {
        match_set_tun_id(match, tc_flow->tunnel.id);
        match_set_tun_src(match, tc_flow->tunnel.ipv4_src);
        match_set_tun_dst(match, tc_flow->tunnel.ipv4_dst);
        match_set_tp_dst(match, tc_flow->tunnel.tp_dst);
    }

    act_off = nl_msg_start_nested(buf, OVS_FLOW_ATTR_ACTIONS);
    {
        if (tc_flow->vlan_pop)
            nl_msg_put_flag(buf, OVS_ACTION_ATTR_POP_VLAN);

        if (tc_flow->vlan_push_id || tc_flow->vlan_push_prio) {
            struct ovs_action_push_vlan *push = nl_msg_put_unspec_zero(buf, OVS_ACTION_ATTR_PUSH_VLAN, sizeof(*push));

            push->vlan_tpid = ntohs(ETH_TYPE_VLAN);
            push->vlan_tci = ntohs(tc_flow->vlan_push_id | (tc_flow->vlan_push_prio << 13) | VLAN_CFI);
        }

        if (tc_flow->ifindex_out > 0) {
            int ifx = netdev_hmap_port_get_byifidx(tc_flow->ifindex_out);

            nl_msg_put_u32(buf, OVS_ACTION_ATTR_OUTPUT, ifx ? ifx : 0xFF);
        }

        if (tc_flow->set.set) {
            size_t set_offset = nl_msg_start_nested(buf, OVS_ACTION_ATTR_SET);
            size_t tunnel_offset = nl_msg_start_nested(buf, OVS_KEY_ATTR_TUNNEL);

            nl_msg_put_be64(buf, OVS_TUNNEL_KEY_ATTR_ID, tc_flow->set.id);
            nl_msg_put_be32(buf, OVS_TUNNEL_KEY_ATTR_IPV4_SRC, tc_flow->set.ipv4_src);
            nl_msg_put_be32(buf, OVS_TUNNEL_KEY_ATTR_IPV4_DST, tc_flow->set.ipv4_dst);
            nl_msg_put_be16(buf, OVS_TUNNEL_KEY_ATTR_TP_DST, tc_flow->set.tp_dst);

            nl_msg_end_nested(buf, tunnel_offset);
            nl_msg_end_nested(buf, set_offset);
        }
    }
    nl_msg_end_nested(buf, act_off);

    *actions = ofpbuf_at_assert(buf, act_off, sizeof(struct nlattr));

    if (stats) {
        memset(stats, 0, sizeof *stats);
        stats->n_packets = get_32aligned_u64(&tc_flow->stats.n_packets);
        stats->n_bytes = get_32aligned_u64(&tc_flow->stats.n_bytes);
        stats->used = tc_flow->lastused;
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
    struct ofpbuf nl_flow;

    for (;;) {
        if (nl_dump_next(dump->nl_dump, &nl_flow, rbuffer)) {
            struct tc_flow tc_flow;
            struct flow *mask = &match->wc.masks;
            ovs_u128 *uf;

            if (parse_tc_flow(&nl_flow, &tc_flow) == EAGAIN) {
                continue;
            }

            parse_tc_flow_to_match(&tc_flow, match, actions, stats, wbuffer);

            uf = find_ufid(tc_flow.prio, tc_flow.handle, dump->netdev);
            if (!uf) {
                VLOG_DBG("unmatched flow dumped: %d, %d %d, creating ufid",
                         tc_flow.prio, tc_flow.handle,
                         netdev_get_ifindex(dump->netdev));
               dpif_flow_hash(NULL, &match->flow, sizeof match->flow, ufid);
               add_ufid_tc_mapping(ufid, tc_flow.prio, tc_flow.handle,
                                   dump->netdev);
            } else {
                *ufid = *uf;
            }

            match_set_in_port(match, dump->port);
            memset(&mask->in_port, 0xFF, sizeof mask->in_port);

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

