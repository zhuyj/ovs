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

#include <config.h>

#include "dpif-gid.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_gid);

static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;

static struct cmap group_id_map = CMAP_INITIALIZER;
static struct cmap group_metadata_map = CMAP_INITIALIZER;

static struct ovs_list group_expiring OVS_GUARDED_BY(mutex)
    = OVS_LIST_INITIALIZER(&group_expiring);
static struct ovs_list expired OVS_GUARDED_BY(mutex)
    = OVS_LIST_INITIALIZER(&expired);

static uint32_t next_group_id OVS_GUARDED_BY(mutex) = 1; /* Possible next free id. */
static void group_id_node_free(struct group_id_node *);

/* This should be called by the revalidator once at each round (every 500ms or
 * more). */
void
group_run(void)
{
    static long long int last = 0;
    long long int now = time_msec();

    /* Do maintenance at most 4 times / sec. */
    ovs_mutex_lock(&mutex);
    if (now - last > 250) {
        struct group_id_node *node;

        last = now;

        LIST_FOR_EACH_POP (node, exp_node, &expired) {
            cmap_remove(&group_id_map, &node->id_node, node->id);
            ovsrcu_postpone(group_id_node_free, node);
        }

        if (!ovs_list_is_empty(&group_expiring)) {
            /* 'expired' is now empty, move nodes in 'group_expiring' to it. */
            ovs_list_splice(&expired, ovs_list_front(&group_expiring),
                            &group_expiring);
        }
    }
    ovs_mutex_unlock(&mutex);
}

/* We use the id as the hash value, which works due to cmap internal rehashing.
 * We also only insert nodes with unique IDs, so all possible hash collisions
 * remain internal to the cmap. */
static struct group_id_node *
group_find__(uint32_t id)
    OVS_REQUIRES(mutex)
{
    struct cmap_node *node = cmap_find_protected(&group_id_map, id);

    return node ? CONTAINER_OF(node, struct group_id_node, id_node) : NULL;
}

/* Lockless RCU protected lookup.  If node is needed accross RCU quiescent
 * state, caller should copy the contents. */
const struct group_id_node *
group_id_node_find(uint32_t id)
{
    const struct cmap_node *node = cmap_find(&group_id_map, id);

    return node
        ? CONTAINER_OF(node, const struct group_id_node, id_node)
        : NULL;
}

static uint32_t
userspace_action_hash(const struct userspace_action *action)
{
    uint32_t hash;

    hash = uuid_hash(&action->cookie.ofproto_uuid);
    hash = hash_int(action->cookie.type, hash);
    hash = hash_int(action->cookie.ofp_in_port, hash);
    hash = hash_int(action->cookie.sflow.vlan_tci, hash);
    hash = hash_int(action->cookie.sflow.output, hash);
    hash = hash_int(action->pid, hash);

    return hash;
}

static bool
userspace_action_equal(const struct userspace_action *a,
                       const struct userspace_action *b)
{
    return (a->cookie.type == b->cookie.type
            && a->cookie.ofp_in_port == b->cookie.ofp_in_port
            && uuid_equals(&a->cookie.ofproto_uuid, &b->cookie.ofproto_uuid)
            && a->cookie.sflow.vlan_tci == b->cookie.sflow.vlan_tci
            && a->cookie.sflow.output == b->cookie.sflow.output
            && a->pid == b->pid);
}

/* Lockless RCU protected lookup.  If node is needed accross RCU quiescent
 * state, caller should take a reference. */
static struct group_id_node *
group_find_equal(const struct userspace_action *target, uint32_t hash)
{
    struct group_id_node *node;

    CMAP_FOR_EACH_WITH_HASH (node, metadata_node, hash, &group_metadata_map) {
        if (userspace_action_equal(&node->action, target)) {
            return node;
        }
    }
    return NULL;
}

static struct group_id_node *
group_ref_equal(const struct userspace_action *target, uint32_t hash)
{
    struct group_id_node *node;

    do {
        node = group_find_equal(target, hash);

        /* Try again if the node was released before we get the reference. */
    } while (node && !ovs_refcount_try_ref_rcu(&node->refcount));

    return node;
}

static void
userspace_action_clone(struct userspace_action *new,
                       const struct userspace_action *old)
{
    *new = *old;
}

/* Allocate a unique group id for the given set of flow metadata.
 * The ID space is 2^^32, so there should never be a situation in which all
 * the IDs are used up.  We loop until we find a free one. */
static struct group_id_node *
group_alloc_id__(const struct userspace_action *action, uint32_t hash)
{
    struct group_id_node *node = xzalloc(sizeof *node);

    node->hash = hash;
    ovs_refcount_init(&node->refcount);
    userspace_action_clone(CONST_CAST(struct userspace_action *, &node->action), action);

    ovs_mutex_lock(&mutex);
    for (;;) {
        node->id = next_group_id++;
        if (OVS_UNLIKELY(!node->id)) {
            next_group_id = 1;
            node->id = next_group_id++;
        }
        /* Find if the id is free. */
        if (OVS_LIKELY(!group_find__(node->id))) {
            break;
        }
    }
    cmap_insert(&group_id_map, &node->id_node, node->id);
    cmap_insert(&group_metadata_map, &node->metadata_node, node->hash);
    ovs_mutex_unlock(&mutex);
    return node;
}

/* Allocate a unique group id for the given set of flow metadata and
   optional actions. */
uint32_t
group_alloc_id_ctx(const struct userspace_action *action)
{
    uint32_t hash = userspace_action_hash(action);
    struct group_id_node *node = group_ref_equal(action, hash);
    if (!node) {
        node = group_alloc_id__(action, hash);
    }
    return node->id;
}

static void
group_id_node_free(struct group_id_node *node)
{
    free(node);
}

void
group_id_node_unref(const struct group_id_node *node_)
    OVS_EXCLUDED(mutex)
{
    struct group_id_node *node = CONST_CAST(struct group_id_node *, node_);

    if (node && ovs_refcount_unref(&node->refcount) == 1) {
        ovs_mutex_lock(&mutex);
        /* Prevent re-use of this node by removing the node from 'metadata_map'
         */
        cmap_remove(&group_metadata_map, &node->metadata_node, node->hash);
        /* We keep the node in the 'group_id_map' so that it can be found as long
         * as it lingers, and add it to the 'group_expiring' list. */
        ovs_list_insert(&group_expiring, &node->exp_node);
        ovs_mutex_unlock(&mutex);
    }
}

void
group_free_id(uint32_t id)
{
    const struct group_id_node *node;

    node = group_id_node_find(id);
    if (node) {
        group_id_node_unref(node);
    } else {
        VLOG_ERR("Freeing nonexistent group ID: %"PRIu32, id);
    }
}

/* Called when 'ofproto' is destructed.  Checks for and clears any
 * group_id leak.
 * No other thread may have access to the 'ofproto' being destructed.
 * All related datapath flows must be deleted before calling this. */
void
group_free_ofproto(struct ofproto_dpif *ofproto, const char *ofproto_name)
{
    struct group_id_node *n;

    CMAP_FOR_EACH (n, metadata_node, &group_metadata_map) {
        if (uuid_equals(&n->action.cookie.ofproto_uuid, &ofproto->uuid)) {
            VLOG_ERR("group_id %"PRIu32
                     " left allocated when ofproto (%s)"
                     " is destructed", n->id, ofproto_name);
        }
    }
}
