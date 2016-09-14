#ifndef DPIF_HW_NETLINK_H
#define DPIF_HW_NETLINK_H 1

#include "ovs-thread.h"
#include "hmap.h"
#include "dpif-provider.h"

/* Datapath interface for the openvswitch Linux kernel module. */
struct dpif_hw_acc {
    struct dpif dpif;
    struct dpif *lp_dpif_netlink;
    const char *const name;
    struct ovs_mutex hash_mutex;
    struct hmap port_to_netdev;
    struct hmap ufid_to_handle;
    struct hmap handle_to_ufid;
    struct hmap ufid_to_policy;
    uint64_t n_last_hits;
    uint64_t n_last_flows;
};

struct port_netdev_hash_data {
    struct hmap_node node;
    struct netdev *netdev;
    odp_port_t port;
};

struct ufid_handle_hash_data {
    struct hmap_node node_ufid;
    struct hmap_node node_handle;
    ovs_u128 ovs_ufid;
    int handle;
    int protocol;
    struct netdev *netdev;
    odp_port_t port;
};

struct ufid_policy_hash_data {
    struct hmap_node node_ufid;
    ovs_u128 ovs_ufid;
    int offloading_policy;
};
#endif
