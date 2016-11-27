#ifndef TC_H
#define TC_H 1

#include "odp-netlink.h"
#include "netlink-socket.h"

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
void tc_set_skip_hw(bool set);

#endif /* tc.h */
