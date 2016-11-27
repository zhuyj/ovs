#ifndef NETDEV_TC_OFFLOADS_H
#define NETDEV_TC_OFFLOADS_H 1

#include "netdev.h"

int netdev_tc_flow_flush(struct netdev *);
struct netdev_flow_dump *netdev_tc_flow_dump_create(struct netdev *);
int netdev_tc_flow_dump_destroy(struct netdev_flow_dump *);
bool netdev_tc_flow_dump_next(struct netdev_flow_dump *, struct match *,
                          struct nlattr **actions, struct dpif_flow_stats *,
                          ovs_u128 *ufid, struct ofpbuf *rbuffer,
                          struct ofpbuf *wbuffer);
int netdev_tc_flow_put(struct netdev *, struct match *, struct nlattr *actions,
                    size_t actions_len, struct dpif_flow_stats *, ovs_u128 *);
int netdev_tc_flow_get(struct netdev *, struct match *, struct nlattr **actions,
                    struct dpif_flow_stats *, ovs_u128 *, struct ofpbuf *);
int netdev_tc_flow_del(struct netdev *, struct dpif_flow_stats *, ovs_u128 *);
int netdev_tc_init_flow_api(struct netdev *);

#endif /* netdev-tc-offloads.h */
