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

#include <errno.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <linux/tc_act/tc_gact.h>
#include <linux/tc_act/tc_mirred.h>
#include <linux/tc_act/tc_vlan.h>
#include <linux/tc_act/tc_tunnel_key.h>
#include <linux/gen_stats.h>
#include "timeval.h"
#include "netlink-socket.h"
#include "netlink.h"
#include "rtnetlink.h"
#include "openvswitch/vlog.h"
#include "openvswitch/ofpbuf.h"
#include "tc.h"
#include "util.h"
#include "byte-order.h"

VLOG_DEFINE_THIS_MODULE(tc);

enum tc_offload_policy {
	TC_POLICY_NONE,
	TC_POLICY_SKIP_SW,
	TC_POLICY_SKIP_HW
};

enum tc_offload_policy tc_policy = TC_POLICY_NONE;

/* Returns tc handle 'major':'minor'. */
static unsigned int
tc_make_handle(unsigned int major, unsigned int minor)
{
    return TC_H_MAKE(major << 16, minor);
}

static struct tcmsg *
tc_make_req(int ifindex, int type, unsigned int flags, struct ofpbuf *request)
{
    struct tcmsg *tcmsg;
    struct nlmsghdr *nlmsghdr;

    ofpbuf_init(request, 512);

    nl_msg_reserve(request, NLMSG_HDRLEN + sizeof *tcmsg);
    nlmsghdr = nl_msg_put_uninit(request, NLMSG_HDRLEN);
    nlmsghdr->nlmsg_len = 0;
    nlmsghdr->nlmsg_type = type;
    nlmsghdr->nlmsg_flags = NLM_F_REQUEST | flags;
    nlmsghdr->nlmsg_seq = 0;
    nlmsghdr->nlmsg_pid = 0;

    tcmsg = ofpbuf_put_zeros(request, sizeof *tcmsg);
    tcmsg->tcm_family = AF_UNSPEC;
    tcmsg->tcm_ifindex = ifindex;

    return tcmsg;
}

static int
tc_transact(struct ofpbuf *request, struct ofpbuf **replyp)
{
    int error = nl_transact(NETLINK_ROUTE, request, replyp);

    ofpbuf_uninit(request);
    return error;
}

static const struct nl_policy tca_policy[] = {
    [TCA_KIND] = { .type = NL_A_STRING, .optional = false, },
    [TCA_OPTIONS] = { .type = NL_A_NESTED, .optional = false, },
    [TCA_STATS] = { .type = NL_A_UNSPEC,
                    .min_len = sizeof(struct tc_stats), .optional = true, },
    [TCA_STATS2] = { .type = NL_A_NESTED, .optional = true, },
};

static const struct nl_policy tca_flower_policy[] = {
    [TCA_FLOWER_CLASSID] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_INDEV] = { .type = NL_A_STRING, .max_len = IFNAMSIZ,
                           .optional = true, },
    [TCA_FLOWER_KEY_ETH_SRC] = { .type = NL_A_UNSPEC,
                                 .min_len = ETH_ALEN, .optional = true, },
    [TCA_FLOWER_KEY_ETH_DST] = { .type = NL_A_UNSPEC,
                                 .min_len = ETH_ALEN, .optional = true, },
    [TCA_FLOWER_KEY_ETH_SRC_MASK] = { .type = NL_A_UNSPEC,
                                      .min_len = ETH_ALEN,
                                      .optional = true, },
    [TCA_FLOWER_KEY_ETH_DST_MASK] = { .type = NL_A_UNSPEC,
                                      .min_len = ETH_ALEN,
                                      .optional = true, },
    [TCA_FLOWER_KEY_ETH_TYPE] = { .type = NL_A_U16, .optional = false, },
    [TCA_FLOWER_FLAGS] = { .type = NL_A_U32, .optional = false, },
    [TCA_FLOWER_ACT] = { .type = NL_A_NESTED, .optional = false, },
    [TCA_FLOWER_KEY_IP_PROTO] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_SRC] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_DST] = {.type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_SRC_MASK] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_DST_MASK] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV6_SRC] = { .type = NL_A_UNSPEC,
                                  .min_len = sizeof(struct in6_addr),
                                  .optional = true, },
    [TCA_FLOWER_KEY_IPV6_DST] = { .type = NL_A_UNSPEC,
                                  .min_len = sizeof(struct in6_addr),
                                  .optional = true, },
    [TCA_FLOWER_KEY_IPV6_SRC_MASK] = { .type = NL_A_UNSPEC,
                                       .min_len = sizeof(struct in6_addr),
                                       .optional = true, },
    [TCA_FLOWER_KEY_IPV6_DST_MASK] = { .type = NL_A_UNSPEC,
                                       .min_len = sizeof(struct in6_addr),
                                       .optional = true, },
    [TCA_FLOWER_KEY_TCP_SRC] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_TCP_DST] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_TCP_SRC_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_TCP_DST_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_SRC] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_DST] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_SRC_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_DST_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_VLAN_ID] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_VLAN_PRIO] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_VLAN_ETH_TYPE] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_ENC_KEY_ID] = { .type = NL_A_BE32, .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV4_SRC] = { .type = NL_A_BE32, .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV4_DST] = { .type = NL_A_BE32, .optional = true, },
    [TCA_FLOWER_KEY_ENC_UDP_DST_PORT] = { .type = NL_A_BE16,
                                          .optional = true, },
};

static int
__nl_parse_flower_eth(struct nlattr **attrs, struct tc_flow *tc_flow)
{
    const struct eth_addr *eth = 0;

    if (attrs[TCA_FLOWER_KEY_ETH_SRC_MASK]) {
        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ETH_SRC], ETH_ALEN);
        memcpy(&tc_flow->key.src_mac, eth, sizeof tc_flow->key.src_mac);

        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ETH_SRC_MASK], ETH_ALEN);
        memcpy(&tc_flow->mask.src_mac, eth, sizeof tc_flow->mask.src_mac);
    }
    if (attrs[TCA_FLOWER_KEY_ETH_DST_MASK]) {
        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ETH_DST], ETH_ALEN);
        memcpy(&tc_flow->key.dst_mac, eth, sizeof tc_flow->key.dst_mac);

        eth = nl_attr_get_unspec(attrs[TCA_FLOWER_KEY_ETH_DST_MASK], ETH_ALEN);
        memcpy(&tc_flow->mask.dst_mac, eth, sizeof tc_flow->mask.dst_mac);
    }
    return 0;
}

static int
__nl_parse_flower_vlan(struct nlattr **attrs, struct tc_flow *tc_flow)
{
    if (tc_flow->key.eth_type != htons(ETH_P_8021Q)) {
       return 0;
    }

    tc_flow->key.encap_eth_type = nl_attr_get_u16(attrs[TCA_FLOWER_KEY_ETH_TYPE]);

    if (attrs[TCA_FLOWER_KEY_VLAN_ID]) {
        tc_flow->key.vlan_id = nl_attr_get_u16(attrs[TCA_FLOWER_KEY_VLAN_ID]);
    }
    if (attrs[TCA_FLOWER_KEY_VLAN_PRIO]) {
        tc_flow->key.vlan_prio = nl_attr_get_u8(attrs[TCA_FLOWER_KEY_VLAN_PRIO]);
    }
    return 0;
}

static int
__nl_parse_flower_tunnel(struct nlattr **attrs, struct tc_flow *tc_flow)
{
    if (attrs[TCA_FLOWER_KEY_ENC_KEY_ID]) {
        ovs_be32 id = nl_attr_get_be32(attrs[TCA_FLOWER_KEY_ENC_KEY_ID]);

        tc_flow->tunnel.id = ntohll((ovs_be64) ntohl(id));
    }
    if (attrs[TCA_FLOWER_KEY_ENC_IPV4_SRC]) {
        tc_flow->tunnel.ipv4_src =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_ENC_IPV4_SRC]);
    }
    if (attrs[TCA_FLOWER_KEY_ENC_IPV4_DST]) {
        tc_flow->tunnel.ipv4_dst =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_ENC_IPV4_DST]);
    }
    if (attrs[TCA_FLOWER_KEY_ENC_UDP_DST_PORT]) {
        tc_flow->tunnel.tp_dst =
            nl_attr_get_be16(attrs[TCA_FLOWER_KEY_ENC_UDP_DST_PORT]);
    }
    return 0;
}

static int
__nl_parse_flower_ip(struct nlattr **attrs, struct tc_flow *tc_flow) {
    uint8_t ip_proto = 0;
    const size_t ipv6_size = sizeof tc_flow->mask.ipv6.ipv6_src;
    struct tc_flow_key *key = &tc_flow->key;
    struct tc_flow_key *mask = &tc_flow->mask;

    if (attrs[TCA_FLOWER_KEY_IP_PROTO]) {
        ip_proto = nl_attr_get_u8(attrs[TCA_FLOWER_KEY_IP_PROTO]);
        key->ip_proto = ip_proto;
        mask->ip_proto = UINT8_MAX;
    }

    if (attrs[TCA_FLOWER_KEY_IPV4_SRC_MASK]) {
        key->ipv4.ipv4_src =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_IPV4_SRC]);
        mask->ipv4.ipv4_src =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_IPV4_SRC_MASK]);
    }
    if (attrs[TCA_FLOWER_KEY_IPV4_DST_MASK]) {
        key->ipv4.ipv4_dst =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_IPV4_DST]);
        mask->ipv4.ipv4_dst =
            nl_attr_get_be32(attrs[TCA_FLOWER_KEY_IPV4_DST_MASK]);
    }
    if (attrs[TCA_FLOWER_KEY_IPV6_SRC_MASK]) {
        struct nlattr *attr = attrs[TCA_FLOWER_KEY_IPV6_SRC];
        struct nlattr *attr_mask = attrs[TCA_FLOWER_KEY_IPV6_SRC_MASK];
        const void *data = nl_attr_get_unspec(attr, ipv6_size);
        const void *mask_data = nl_attr_get_unspec(attr_mask, ipv6_size);

        memcpy(&key->ipv6.ipv6_src, data, ipv6_size);
        memcpy(&mask->ipv6.ipv6_src, mask_data, ipv6_size);
    }
    if (attrs[TCA_FLOWER_KEY_IPV6_DST_MASK]) {
        struct nlattr *attr = attrs[TCA_FLOWER_KEY_IPV6_DST];
        struct nlattr *attr_mask = attrs[TCA_FLOWER_KEY_IPV6_DST_MASK];
        const void *data = nl_attr_get_unspec(attr, ipv6_size);
        const void *mask_data = nl_attr_get_unspec(attr_mask, ipv6_size);

        memcpy(&key->ipv6.ipv6_dst, data, ipv6_size);
        memcpy(&mask->ipv6.ipv6_dst, mask_data, ipv6_size);
    }

    if (ip_proto == IPPROTO_TCP) {
        if (attrs[TCA_FLOWER_KEY_TCP_SRC_MASK]) {
            key->src_port =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_SRC]);
            mask->src_port =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_SRC_MASK]);
        }
        if (attrs[TCA_FLOWER_KEY_TCP_DST_MASK]) {
            key->dst_port =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_DST]);
            mask->dst_port =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_TCP_DST_MASK]);
        }
    } else if (ip_proto == IPPROTO_UDP) {
        if (attrs[TCA_FLOWER_KEY_UDP_SRC_MASK]) {
            key->src_port = nl_attr_get_be16(attrs[TCA_FLOWER_KEY_UDP_SRC]);
            mask->src_port =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_UDP_SRC_MASK]);
        }
        if (attrs[TCA_FLOWER_KEY_UDP_DST_MASK]) {
            key->dst_port = nl_attr_get_be16(attrs[TCA_FLOWER_KEY_UDP_DST]);
            mask->dst_port =
                nl_attr_get_be16(attrs[TCA_FLOWER_KEY_UDP_DST_MASK]);
        }
    }

    return 0;
}

static const struct nl_policy tunnel_key_policy[] = {
    [TCA_TUNNEL_KEY_PARMS] = { .type = NL_A_UNSPEC,
                               .min_len = sizeof(struct tc_tunnel_key),
                               .optional = false, },
    [TCA_TUNNEL_KEY_ENC_KEY_ID] = { .type = NL_A_BE32, .optional = true, },
    [TCA_TUNNEL_KEY_ENC_DST_PORT] = { .type = NL_A_BE16, .optional = true, },
    [TCA_TUNNEL_KEY_ENC_IPV4_SRC] = { .type = NL_A_BE32, .optional = true, },
    [TCA_TUNNEL_KEY_ENC_IPV4_DST] = { .type = NL_A_BE32, .optional = true, },
};

static int
__nl_parse_act_tunnel_key(struct nlattr *options, struct tc_flow *tc_flow)
{
    struct nlattr *tun_attrs[ARRAY_SIZE(tunnel_key_policy)];
    const struct nlattr *tun_parms;
    const struct tc_tunnel_key *tun;

    if (!nl_parse_nested(options, tunnel_key_policy, tun_attrs,
                ARRAY_SIZE(tunnel_key_policy))) {
        VLOG_ERR("failed to parse tunnel_key action options");
        return EPROTO;
    }

    tun_parms = tun_attrs[TCA_TUNNEL_KEY_PARMS];
    tun = nl_attr_get_unspec(tun_parms, sizeof *tun);
    if (tun->t_action == TCA_TUNNEL_KEY_ACT_SET) {
        struct nlattr *id = tun_attrs[TCA_TUNNEL_KEY_ENC_KEY_ID];
        struct nlattr *dst_port = tun_attrs[TCA_TUNNEL_KEY_ENC_DST_PORT];
        struct nlattr *ipv4_src = tun_attrs[TCA_TUNNEL_KEY_ENC_IPV4_SRC];
        struct nlattr *ipv4_dst = tun_attrs[TCA_TUNNEL_KEY_ENC_IPV4_DST];

        tc_flow->set.set = true;
        tc_flow->set.ipv4_src = ipv4_src ? nl_attr_get_be32(ipv4_src) : 0;
        tc_flow->set.ipv4_dst = ipv4_dst ? nl_attr_get_be32(ipv4_dst) : 0;
        tc_flow->set.id = ntohll(((ovs_be64) ntohl(nl_attr_get_be32(id))));
        tc_flow->set.tp_dst = dst_port ? nl_attr_get_be16(dst_port) : 0;
    } else if (tun->t_action == TCA_TUNNEL_KEY_ACT_RELEASE) {
        tc_flow->tunnel.tunnel = true;
    } else {
        VLOG_ERR("unknown tunnel actions: %d, %d", tun->action, tun->t_action);
        return EINVAL;
    }
    return 0;
}

static const struct nl_policy gact_policy[] = {
    [TCA_GACT_PARMS] = { .type = NL_A_UNSPEC,
                         .min_len = sizeof(struct tc_gact),
                         .optional = false, },
    [TCA_GACT_TM] = { .type = NL_A_UNSPEC,
                      .min_len = sizeof(struct tcf_t),
                      .optional = false, },
};

static void
__nl_parse_tcf(const struct tcf_t *tm, struct tc_flow *tc_flow)
{
    unsigned long long int lastuse = tm->lastuse * 10;
    unsigned long long int now = time_msec();

    tc_flow->lastused = now - lastuse;
}

static int
__nl_parse_act_drop(struct nlattr *options, struct tc_flow *tc_flow)
{
    struct nlattr *gact_attrs[ARRAY_SIZE(gact_policy)];
    const struct tc_gact *p;
    struct nlattr *gact_parms;
    const struct tcf_t *tm;

    if (!nl_parse_nested(options, gact_policy, gact_attrs,
                         ARRAY_SIZE(gact_policy))) {
        VLOG_ERR("failed to parse gact action options");
        return EPROTO;
    }

    gact_parms = gact_attrs[TCA_GACT_PARMS];
    p = nl_attr_get_unspec(gact_parms, sizeof *p);

    if (p->action == TC_ACT_SHOT) {
    } else {
            VLOG_ERR("unknown gact action: %d", p->action);
            return EINVAL;
    }

    tm = nl_attr_get_unspec(gact_attrs[TCA_GACT_TM], sizeof *tm);
    __nl_parse_tcf(tm, tc_flow);

    return 0;
}

static const struct nl_policy mirred_policy[] = {
    [TCA_MIRRED_PARMS] = { .type = NL_A_UNSPEC,
                           .min_len = sizeof(struct tc_mirred),
                           .optional = false, },
    [TCA_MIRRED_TM] = { .type = NL_A_UNSPEC,
                        .min_len = sizeof(struct tcf_t),
                        .optional = false, },
};

static int
__nl_parse_act_mirred(struct nlattr *options, struct tc_flow *tc_flow)
{

    struct nlattr *mirred_attrs[ARRAY_SIZE(mirred_policy)];
    const struct tc_mirred *m;
    const struct nlattr *mirred_parms;
    const struct tcf_t *tm;
    struct nlattr *mirred_tm;

    if (!nl_parse_nested(options, mirred_policy, mirred_attrs,
                         ARRAY_SIZE(mirred_policy))) {
        VLOG_ERR("failed to parse mirred action options");
        return EPROTO;
    }

    mirred_parms = mirred_attrs[TCA_MIRRED_PARMS];
    m = nl_attr_get_unspec(mirred_parms, sizeof *m);

    if (m->action != TC_ACT_STOLEN ||  m->eaction != TCA_EGRESS_REDIR) {
        VLOG_ERR("unknown mirred action: %d, %d, %d",
                 m->action, m->eaction, m->ifindex);
        return EINVAL;
    }

    tc_flow->ifindex_out = m->ifindex;

    mirred_tm = mirred_attrs[TCA_MIRRED_TM];
    tm = nl_attr_get_unspec(mirred_tm, sizeof *tm);
    __nl_parse_tcf(tm, tc_flow);

    return 0;
}

static const struct nl_policy vlan_policy[] = {
    [TCA_VLAN_PARMS] = { .type = NL_A_UNSPEC,
                         .min_len = sizeof(struct tc_vlan),
                         .optional = false, },
    [TCA_VLAN_PUSH_VLAN_ID] = { .type = NL_A_U16, .optional = true, },
    [TCA_VLAN_PUSH_VLAN_PROTOCOL] = { .type = NL_A_U16, .optional = true, },
    [TCA_VLAN_PUSH_VLAN_PRIORITY] = { .type = NL_A_U8, .optional = true, },
};

static int
__nl_parse_act_vlan(struct nlattr *options, struct tc_flow *tc_flow)
{
    struct nlattr *vlan_attrs[ARRAY_SIZE(vlan_policy)];
    const struct tc_vlan *v;
    const struct nlattr *vlan_parms;

    if (!nl_parse_nested(options, vlan_policy, vlan_attrs,
                         ARRAY_SIZE(vlan_policy))) {
        VLOG_ERR("failed to parse vlan action options");
        return EPROTO;
    }

    vlan_parms = vlan_attrs[TCA_VLAN_PARMS];
    v = nl_attr_get_unspec(vlan_parms, sizeof *v);
    if (v->v_action == TCA_VLAN_ACT_PUSH) {
        struct nlattr *vlan_id = vlan_attrs[TCA_VLAN_PUSH_VLAN_ID];
        struct nlattr *vlan_prio = vlan_attrs[TCA_VLAN_PUSH_VLAN_PRIORITY];

        tc_flow->vlan_push_id = nl_attr_get_u16(vlan_id);
        tc_flow->vlan_push_prio = nl_attr_get_u8(vlan_prio);
    } else if (v->v_action == TCA_VLAN_ACT_POP) {
        tc_flow->vlan_pop = 1;
    } else {
        VLOG_ERR("unknown vlan action: %d, %d", v->action, v->v_action);
        return EINVAL;
    }
    return 0;
}

static const struct nl_policy act_policy[] = {
    [TCA_ACT_KIND] = { .type = NL_A_STRING, .optional = false, },
    [TCA_ACT_OPTIONS] = { .type = NL_A_NESTED, .optional = false, },
    [TCA_ACT_STATS] = { .type = NL_A_NESTED, .optional = false, },
};

static const struct nl_policy stats_policy[] = {
    [TCA_STATS_BASIC] = { .type = NL_A_UNSPEC,
                          .min_len = sizeof(struct gnet_stats_basic),
                          .optional = false, },
};

static int
__nl_parse_single_action(struct nlattr *action, struct tc_flow *tc_flow)
{
    struct nlattr *act_options;
    struct nlattr *act_stats;
    const struct nlattr *stats_basic;
    const char *act_kind;
    struct nlattr *action_attrs[ARRAY_SIZE(act_policy)];
    struct nlattr *stats_attrs[ARRAY_SIZE(stats_policy)];
    struct ovs_flow_stats *stats = &tc_flow->stats;
    const struct gnet_stats_basic *bs;

    if (!nl_parse_nested(action, act_policy, action_attrs,
                         ARRAY_SIZE(act_policy))) {
        VLOG_ERR("failed to parse single action options");
        return EPROTO;
    }

    act_kind = nl_attr_get_string(action_attrs[TCA_ACT_KIND]);
    act_options = action_attrs[TCA_ACT_OPTIONS];

    if (!strcmp(act_kind, "gact")) {
        __nl_parse_act_drop(act_options, tc_flow);
    } else if (!strcmp(act_kind, "mirred")) {
        __nl_parse_act_mirred(act_options, tc_flow);
    } else if (!strcmp(act_kind, "vlan")) {
        __nl_parse_act_vlan(act_options, tc_flow);
    } else if (!strcmp(act_kind, "tunnel_key")) {
        __nl_parse_act_tunnel_key(act_options, tc_flow);
    } else {
        VLOG_ERR("unknown tc action, kind %s", act_kind);
        return EINVAL;
    }

    act_stats = action_attrs[TCA_ACT_STATS];

    if (!nl_parse_nested(act_stats, stats_policy, stats_attrs,
                         ARRAY_SIZE(stats_policy))) {
        VLOG_ERR("failed to parse action stats policy");
        return EPROTO;
    }

    stats_basic = stats_attrs[TCA_STATS_BASIC];
    bs = nl_attr_get_unspec(stats_basic, sizeof *bs);

    stats->n_packets.lo = bs->packets;
    stats->n_packets.hi = 0;
    stats->n_bytes.hi = bs->bytes >> 32;
    stats->n_bytes.lo = bs->bytes & 0x00000000FFFFFFFF;

    return 0;
}

static int
__nl_parse_flower_actions(struct nlattr **attrs, struct tc_flow *tc_flow)
{
    const struct nlattr *actions = attrs[TCA_FLOWER_ACT];
    static struct nl_policy actions_orders_policy[TCA_ACT_MAX_PRIO + 1] = { };
    struct nlattr *actions_orders[ARRAY_SIZE(actions_orders_policy)];

    for (int i = 0; i < TCA_ACT_MAX_PRIO + 1; i++) {
        actions_orders_policy[i].type = NL_A_NESTED;
        actions_orders_policy[i].optional = true;
    }

    if (!nl_parse_nested(actions, actions_orders_policy, actions_orders,
                         ARRAY_SIZE(actions_orders_policy))) {
        VLOG_ERR("failed to parse flower order of actions");
        return EPROTO;
    }

    for (int i = 1; i < TCA_ACT_MAX_PRIO + 1; i++) {
        if (actions_orders[i]) {
            int err = __nl_parse_single_action(actions_orders[i], tc_flow);
            if (err) {
                return err;
            }
        }
    }

    return 0;
}

static int
__nl_parse_flower_options(struct nlattr *nl_options, struct tc_flow *tc_flow)
{
    struct nlattr *attrs[ARRAY_SIZE(tca_flower_policy)];
    int err = 0;

    if (!nl_parse_nested(nl_options, tca_flower_policy,
                         attrs, ARRAY_SIZE(tca_flower_policy))) {
        VLOG_ERR("failed to parse flower classifier options");
        return EPROTO;
    }

    err = __nl_parse_flower_eth(attrs, tc_flow);
    err = err ? err : __nl_parse_flower_vlan(attrs, tc_flow);
    err = err ? err : __nl_parse_flower_ip(attrs, tc_flow);
    err = err ? err : __nl_parse_flower_tunnel(attrs, tc_flow);
    err = err ? err : __nl_parse_flower_actions(attrs, tc_flow);

    return err;
}

int
parse_tc_flow(struct ofpbuf *reply, struct tc_flow *tc_flow)
{
    struct tcmsg *tc;
    struct nlattr *ta[ARRAY_SIZE(tca_policy)];
    const char *kind;

    memset(tc_flow, 0, sizeof *tc_flow);
    if (NLMSG_HDRLEN + (sizeof *tc) > reply->size) {
        return EPROTO;
    }

    tc = ofpbuf_at_assert(reply, NLMSG_HDRLEN, sizeof *tc);
    tc_flow->handle = tc->tcm_handle;
    tc_flow->key.eth_type = TC_H_MIN(tc->tcm_info);
    tc_flow->mask.eth_type = OVS_BE16_MAX;
    tc_flow->prio = TC_H_MAJ(tc->tcm_info) >> 16;

    if (!tc_flow->handle) {
        return EAGAIN;
    }

    if (!nl_policy_parse(reply, NLMSG_HDRLEN + sizeof *tc,
                         tca_policy, ta, ARRAY_SIZE(ta))) {
        VLOG_ERR("failed to parse tca policy");
        return EPROTO;
    }

    kind = nl_attr_get_string(ta[TCA_KIND]);
    if (strcmp(kind, "flower")) {
        VLOG_ERR("failed to parse filter, filter is not flower");
        return EPROTO;
    }

    return __nl_parse_flower_options(ta[TCA_OPTIONS], tc_flow);
}

int
tc_dump_flower_start(int ifindex, struct nl_dump *dump)
{
    struct ofpbuf request;
    struct tcmsg *tcmsg;

    tcmsg = tc_make_req(ifindex, RTM_GETTFILTER, NLM_F_DUMP, &request);
    tcmsg->tcm_parent = tc_make_handle(0xffff, 0);
    tcmsg->tcm_info = tc_make_handle(0, 0);
    tcmsg->tcm_handle = 0;

    nl_dump_start(dump, NETLINK_ROUTE, &request);
    ofpbuf_uninit(&request);

    return 0;
}

int
tc_flush_flower(int ifindex)
{
    struct ofpbuf request;
    struct tcmsg *tcmsg;

    tcmsg = tc_make_req(ifindex, RTM_DELTFILTER, NLM_F_ACK, &request);
    tcmsg->tcm_parent = tc_make_handle(0xffff, 0);
    tcmsg->tcm_info = tc_make_handle(0, 0);

    return tc_transact(&request, 0);
}

int
tc_del_flower(int ifindex, int handle, int prio)
{
    struct ofpbuf request;
    struct tcmsg *tcmsg;
    struct ofpbuf *reply;

    tcmsg = tc_make_req(ifindex, RTM_DELTFILTER, NLM_F_ECHO, &request);
    tcmsg->tcm_parent = tc_make_handle(0xffff, 0);
    tcmsg->tcm_info = tc_make_handle(prio, 0);
    tcmsg->tcm_handle = handle;

    return tc_transact(&request, &reply);
}

int
tc_get_flower(int ifindex, int handle, int prio, struct tc_flow *tc_flow)
{
    struct ofpbuf request;
    int error = 0;
    struct tcmsg *tcmsg;
    struct ofpbuf *reply;

    tcmsg = tc_make_req(ifindex, RTM_GETTFILTER, NLM_F_ECHO, &request);
    tcmsg->tcm_parent = tc_make_handle(0xffff, 0);
    tcmsg->tcm_info = tc_make_handle(prio, 0);
    tcmsg->tcm_handle = handle;

    error = tc_transact(&request, &reply);
    if (error) {
        return error;
    }

    parse_tc_flow(reply, tc_flow);
    return error;
}

static int
tc_get_tc_cls_policy(enum tc_offload_policy policy)
{
    if (policy == TC_POLICY_SKIP_HW)
        return TCA_CLS_FLAGS_SKIP_HW;
    else if (policy == TC_POLICY_SKIP_SW)
        return TCA_CLS_FLAGS_SKIP_SW;
    else
        return 0;
}

void
tc_set_policy(const char *policy)
{
    if (!policy) {
       return;
    }

    if (!strcmp(policy, "skip_sw")) {
        tc_policy = TC_POLICY_SKIP_SW;
    } else if (!strcmp(policy, "skip_hw")) {
        tc_policy = TC_POLICY_SKIP_HW;
    } else if (!strcmp(policy, "none")) {
        tc_policy = TC_POLICY_NONE;
    } else {
        VLOG_WARN("tc: Invalid policy '%s'", policy);
        return;
    }

    VLOG_INFO("tc: Using policy '%s'", policy);
}

static void
__nl_msg_put_act_push_vlan(struct ofpbuf *request, uint16_t vid, uint8_t prio)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "vlan");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_vlan parm = { 0 };

        parm.action = TC_ACT_PIPE;
        parm.v_action = TCA_VLAN_ACT_PUSH;
        nl_msg_put_unspec(request, TCA_VLAN_PARMS, &parm, sizeof parm);
        nl_msg_put_u16(request, TCA_VLAN_PUSH_VLAN_ID, vid);
        nl_msg_put_u8(request, TCA_VLAN_PUSH_VLAN_PRIORITY, prio);
    }
    nl_msg_end_nested(request, offset);
}

static void
__nl_msg_put_act_pop_vlan(struct ofpbuf *request)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "vlan");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_vlan parm = { 0 };

        parm.action = TC_ACT_PIPE;
        parm.v_action = TCA_VLAN_ACT_POP;
        nl_msg_put_unspec(request, TCA_VLAN_PARMS, &parm, sizeof parm);
    }
    nl_msg_end_nested(request, offset);
}

static void
__nl_msg_put_act_tunnel_key_release(struct ofpbuf *request)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "tunnel_key");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_tunnel_key tun = { 0 };

        tun.action = TC_ACT_PIPE;
        tun.t_action = TCA_TUNNEL_KEY_ACT_RELEASE;
        nl_msg_put_unspec(request, TCA_TUNNEL_KEY_PARMS, &tun, sizeof tun);
    }
    nl_msg_end_nested(request, offset);
}

static void
__nl_msg_put_act_tunnel_key_set(struct ofpbuf *request, ovs_be64 id,
                                ovs_be32 ipv4_src, ovs_be32 ipv4_dst,
                                ovs_be16 tp_dst)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "tunnel_key");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_tunnel_key tun = { 0 };

        tun.action = TC_ACT_PIPE;
        tun.t_action = TCA_TUNNEL_KEY_ACT_SET;
        nl_msg_put_unspec(request, TCA_TUNNEL_KEY_PARMS, &tun, sizeof tun);

        ovs_be32 id32 = htonl((ovs_be32) ntohll(id));
        nl_msg_put_be32(request, TCA_TUNNEL_KEY_ENC_KEY_ID, id32);
        nl_msg_put_be32(request, TCA_TUNNEL_KEY_ENC_IPV4_SRC, ipv4_src);
        nl_msg_put_be32(request, TCA_TUNNEL_KEY_ENC_IPV4_DST, ipv4_dst);
        nl_msg_put_be16(request, TCA_TUNNEL_KEY_ENC_DST_PORT, tp_dst);
    }
    nl_msg_end_nested(request, offset);
}

static void
__nl_msg_put_act_drop(struct ofpbuf *request)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "gact");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_gact p = { 0 };

        p.action = TC_ACT_SHOT;
        nl_msg_put_unspec(request, TCA_GACT_PARMS, &p, sizeof p);
    }
    nl_msg_end_nested(request, offset);
}

static void
__nl_msg_put_act_redirect(struct ofpbuf *request, int ifindex)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "mirred");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_mirred m = { 0 };

        m.eaction = TCA_EGRESS_REDIR;
        m.action = TC_ACT_STOLEN;
        m.ifindex = ifindex;

        nl_msg_put_unspec(request, TCA_MIRRED_PARMS, &m, sizeof m);
    }
    nl_msg_end_nested(request, offset);
}

static void
__nl_msg_put_flower_acts(struct ofpbuf *request, struct tc_flow *tc_flow)
{
    size_t offset;
    size_t act_offset;

    offset = nl_msg_start_nested(request, TCA_FLOWER_ACT);
    {
        uint16_t act_index = 1;
        bool done = false;

        while (!done) {
            act_offset = nl_msg_start_nested(request, act_index);
            {
                /* vlan push/pop can only be first, only one output */
                if (tc_flow->set.set && act_index == 1) {
                    __nl_msg_put_act_tunnel_key_set(request, tc_flow->set.id,
                                                    tc_flow->set.ipv4_src,
                                                    tc_flow->set.ipv4_dst,
                                                    tc_flow->set.tp_dst);
                } else if (tc_flow->tunnel.tunnel && act_index == 1) {
                    __nl_msg_put_act_tunnel_key_release(request);
                } else if (tc_flow->vlan_push_id && act_index == 1) {
                    __nl_msg_put_act_push_vlan(request,
                                               tc_flow->vlan_push_id,
                                               tc_flow->vlan_push_prio);
                } else if (tc_flow->vlan_pop && act_index == 1) {
                    __nl_msg_put_act_pop_vlan(request);
                } else if (!tc_flow->ifindex_out) {
                    __nl_msg_put_act_drop(request);
                    done = true;
                } else {
                    __nl_msg_put_act_redirect(request, tc_flow->ifindex_out);
                    done = true;
                }
            }
            nl_msg_end_nested(request, act_offset);
            act_index++;
        }
    }
    nl_msg_end_nested(request, offset);
}

static void
__nl_msg_put_masked_value(struct ofpbuf *request, uint16_t type,
                          uint16_t mask_type, const void *data,
                          const void *mask_data, size_t len)
{
    if (mask_type != TCA_FLOWER_UNSPEC) {
        if (is_all_zeros(mask_data, len)) {
            return;
        }
        nl_msg_put_unspec(request, mask_type, mask_data, len);
    }
    nl_msg_put_unspec(request, type, data, len);
}

static void
__nl_msg_put_flower_tunnel(struct ofpbuf *request, struct tc_flow *tc_flow)
{
    ovs_be32 ipv4_src = tc_flow->tunnel.ipv4_src;
    ovs_be32 ipv4_dst = tc_flow->tunnel.ipv4_dst;
    ovs_be16 tp_dst = tc_flow->tunnel.tp_dst;
    ovs_be32 id = ntohl((ovs_be32) ntohll(tc_flow->tunnel.id));

    nl_msg_put_be32(request, TCA_FLOWER_KEY_ENC_KEY_ID, id);
    nl_msg_put_be32(request, TCA_FLOWER_KEY_ENC_IPV4_SRC, ipv4_src);
    nl_msg_put_be32(request, TCA_FLOWER_KEY_ENC_IPV4_DST, ipv4_dst);
    nl_msg_put_be16(request, TCA_FLOWER_KEY_ENC_UDP_DST_PORT, tp_dst);
}

static void
__nl_msg_put_flower_options(struct ofpbuf *request, struct tc_flow *tc_flow)
{
    uint16_t host_eth_type = ntohs(tc_flow->key.eth_type);

    __nl_msg_put_masked_value(request,
                              TCA_FLOWER_KEY_ETH_DST,
                              TCA_FLOWER_KEY_ETH_DST_MASK,
                              &tc_flow->key.dst_mac,
                              &tc_flow->mask.dst_mac, ETH_ALEN);
    __nl_msg_put_masked_value(request,
                              TCA_FLOWER_KEY_ETH_SRC,
                              TCA_FLOWER_KEY_ETH_SRC_MASK,
                              &tc_flow->key.src_mac,
                              &tc_flow->mask.src_mac, ETH_ALEN);

    if (host_eth_type == ETH_P_IP || host_eth_type == ETH_P_IPV6) {
        if (tc_flow->mask.ip_proto && tc_flow->key.ip_proto) {
            nl_msg_put_u8(request, TCA_FLOWER_KEY_IP_PROTO, tc_flow->key.ip_proto);
        }
        if (tc_flow->key.ip_proto == IPPROTO_UDP) {
            __nl_msg_put_masked_value(request,
                                      TCA_FLOWER_KEY_UDP_SRC,
                                      TCA_FLOWER_KEY_UDP_SRC_MASK,
                                      &tc_flow->key.src_port,
                                      &tc_flow->mask.src_port, 2);
            __nl_msg_put_masked_value(request,
                                      TCA_FLOWER_KEY_UDP_DST,
                                      TCA_FLOWER_KEY_UDP_DST_MASK,
                                      &tc_flow->key.dst_port,
                                      &tc_flow->mask.dst_port, 2);
        } else if (tc_flow->key.ip_proto == IPPROTO_TCP) {
            __nl_msg_put_masked_value(request,
                                      TCA_FLOWER_KEY_TCP_SRC,
                                      TCA_FLOWER_KEY_TCP_SRC_MASK,
                                      &tc_flow->key.src_port,
                                      &tc_flow->mask.src_port, 2);
            __nl_msg_put_masked_value(request,
                                      TCA_FLOWER_KEY_TCP_DST,
                                      TCA_FLOWER_KEY_TCP_DST_MASK,
                                      &tc_flow->key.dst_port,
                                      &tc_flow->mask.dst_port, 2);
        }
    }
    if (host_eth_type == ETH_P_IP) {
            __nl_msg_put_masked_value(request,
                                      TCA_FLOWER_KEY_IPV4_SRC,
                                      TCA_FLOWER_KEY_IPV4_SRC_MASK,
                                      &tc_flow->key.ipv4.ipv4_src,
                                      &tc_flow->mask.ipv4.ipv4_src,
                                      sizeof tc_flow->key.ipv4.ipv4_src);
            __nl_msg_put_masked_value(request,
                                      TCA_FLOWER_KEY_IPV4_DST,
                                      TCA_FLOWER_KEY_IPV4_DST_MASK,
                                      &tc_flow->key.ipv4.ipv4_dst,
                                      &tc_flow->mask.ipv4.ipv4_dst,
                                      sizeof tc_flow->key.ipv4.ipv4_dst);
    } else if (host_eth_type == ETH_P_IPV6) {
            __nl_msg_put_masked_value(request,
                                      TCA_FLOWER_KEY_IPV6_SRC,
                                      TCA_FLOWER_KEY_IPV6_SRC_MASK,
                                      &tc_flow->key.ipv6.ipv6_src,
                                      &tc_flow->mask.ipv6.ipv6_src,
                                      sizeof tc_flow->key.ipv6.ipv6_src);
            __nl_msg_put_masked_value(request,
                                      TCA_FLOWER_KEY_IPV6_DST,
                                      TCA_FLOWER_KEY_IPV6_DST_MASK,
                                      &tc_flow->key.ipv6.ipv6_dst,
                                      &tc_flow->mask.ipv6.ipv6_dst,
                                      sizeof tc_flow->key.ipv6.ipv6_dst);
    }

    nl_msg_put_be16(request, TCA_FLOWER_KEY_ETH_TYPE, tc_flow->key.eth_type);

    if (host_eth_type == ETH_P_8021Q) {
        if (tc_flow->key.vlan_id || tc_flow->key.vlan_prio) {
            nl_msg_put_u16(request, TCA_FLOWER_KEY_VLAN_ID, tc_flow->key.vlan_id);
            nl_msg_put_u8(request, TCA_FLOWER_KEY_VLAN_PRIO,
                          tc_flow->key.vlan_prio);
        }
        if (tc_flow->key.encap_eth_type) {
            nl_msg_put_be16(request, TCA_FLOWER_KEY_VLAN_ETH_TYPE,
                            tc_flow->key.encap_eth_type);
        }
        /* TODO: support for encap ipv4/ipv6 here */
    }

    nl_msg_put_u32(request, TCA_FLOWER_FLAGS, tc_get_tc_cls_policy(tc_policy));

    if (tc_flow->tunnel.tunnel) {
        __nl_msg_put_flower_tunnel(request, tc_flow);
    }

    __nl_msg_put_flower_acts(request, tc_flow);
}

int
tc_replace_flower(struct tc_flow *tc_flow, uint16_t prio)
{
    struct ofpbuf request;
    struct tcmsg *tcmsg;
    struct ofpbuf *reply;
    int error = 0;
    size_t basic_offset;

    tcmsg = tc_make_req(tc_flow->ifindex, RTM_NEWTFILTER,
                        NLM_F_CREATE | NLM_F_ECHO, &request);
    tcmsg->tcm_parent = tc_make_handle(0xffff, 0);
    tcmsg->tcm_info = tc_make_handle((OVS_FORCE uint16_t) prio,
                                     (OVS_FORCE uint16_t) tc_flow->key.eth_type);
    tcmsg->tcm_handle = tc_flow->handle;

    /* flower */
    nl_msg_put_string(&request, TCA_KIND, "flower");
    basic_offset = nl_msg_start_nested(&request, TCA_OPTIONS);
    {
        __nl_msg_put_flower_options(&request, tc_flow);
    }
    nl_msg_end_nested(&request, basic_offset);

    error = tc_transact(&request, &reply);
    if (!error) {
        struct tcmsg *tc =
            ofpbuf_at_assert(reply, NLMSG_HDRLEN, sizeof *tc);

        tc_flow->prio = TC_H_MAJ(tc->tcm_info) >> 16;
        tc_flow->handle = tc->tcm_handle;
    }

    return error;
}
