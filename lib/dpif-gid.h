/*
 * Copyright (c) 2020 Mellanox Technologies, Ltd.
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

#ifndef OFPROTO_DPIF_GID_H
#define OFPROTO_DPIF_GID_H

#include <stddef.h>
#include <stdint.h>

#include "cmap.h"
#include "openvswitch/list.h"
#include "uuid.h"
#include "odp-util.h"
#include "ofproto/ofproto-dpif.h"

struct userspace_action {
    uint32_t pid;       /* netlink PID */
    uint32_t rate;      /* sample rate */
    struct user_action_cookie cookie;
};

/* This maps a group ID and struct userspace_action for sflow */
struct group_id_node {
    struct ovs_list exp_node OVS_GUARDED;
    struct cmap_node metadata_node;
    struct cmap_node id_node;
    struct ovs_refcount refcount;
    uint32_t hash;
    uint32_t id;

    const struct userspace_action action;
};

uint32_t group_alloc_id_ctx(const struct userspace_action *);
void group_free_id(uint32_t group_id);
void group_free_ofproto(struct ofproto_dpif *, const char *ofproto_name);
const struct group_id_node *group_id_node_find(uint32_t group_id);
void group_id_node_unref(const struct group_id_node *);
void group_run(void);

#endif
