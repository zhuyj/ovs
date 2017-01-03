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

#ifndef TC_H
#define TC_H 1

#include "odp-netlink.h"
#include "netlink-socket.h"

#define TC_POLICY_DEFAULT "none"

struct netdev;

struct tc_flow_key {
    ovs_be16 eth_type;
    uint8_t ip_proto;

    struct eth_addr dst_mac;
    struct eth_addr src_mac;

    uint16_t src_port;
    uint16_t dst_port;

    uint16_t vlan_id;
    uint8_t vlan_prio;

    ovs_be16 encap_eth_type;
    uint8_t encap_ip_proto;
    union {
        struct {
            ovs_be32 ipv4_src;
            ovs_be32 ipv4_dst;
        } encap_ipv4;
        struct {
            ovs_be32 ipv6_src[4];
            ovs_be32 ipv6_dst[4];
        } encap_ipv6;
    };

    union {
        struct {
            ovs_be32 ipv4_src;
            ovs_be32 ipv4_dst;
        } ipv4;
        struct {
            ovs_be32 ipv6_src[4];
            ovs_be32 ipv6_dst[4];
        } ipv6;
    };
};

struct tc_flow {
    struct tc_flow_key key;
    struct tc_flow_key mask;

    uint8_t vlan_pop;
    uint16_t vlan_push_id;
    uint8_t vlan_push_prio;

    uint32_t handle;
    uint32_t prio;

    int ifindex;
    int ifindex_out;

    struct ovs_flow_stats stats;
    uint64_t lastused;

    struct {
        bool set;
        ovs_be32 ipv4_src;
        ovs_be32 ipv4_dst;
        ovs_be64 id;
        ovs_be16 tp_src;
        ovs_be16 tp_dst;
    } set;

    struct {
        bool tunnel;
        ovs_be32 ipv4_src;
        ovs_be32 ipv4_dst;
        ovs_be64 id;
        ovs_be16 tp_src;
        ovs_be16 tp_dst;
    } tunnel;
};

int tc_replace_flower(struct tc_flow *flow, uint16_t prio);
int tc_del_flower(int ifindex, int handle, int prio);
int tc_get_flower(int ifindex, int handle, int prio, struct tc_flow *tc_flow);
int tc_flush_flower(int ifindex);
int tc_dump_flower_start(int ifindex, struct nl_dump *dump);
int parse_tc_flow(struct ofpbuf *reply, struct tc_flow *tc_flow);
void tc_set_policy(const char *policy);

#endif /* tc.h */
