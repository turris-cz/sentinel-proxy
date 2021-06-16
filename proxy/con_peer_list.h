/*
 *  Turris:Sentinel Proxy - Main MQTT gateway to Sentinel infrastructure
 *  Copyright (C) 2018 - 2021 CZ.NIC z.s.p.o. (https://www.nic.cz/)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef __SENTINEL_PROXY_CON_PEER_LIST_H__
#define __SENTINEL_PROXY_CON_PEER_LIST_H__

#include "common.h"

#define CON_PEER_TOPIC_MEM_LEN (ZMQ_MAX_TOPIC_LEN + 1)
#define CON_PEER_LIST_DEFAULT_LEN 4

struct con_peer {
	int fd;
	char *topic;
};

struct con_peer_list {
	size_t alloc_size;
	struct con_peer *peers;
};

// Initializes statically or dynamically allocated con_peer struct.
// fd is set to -1. topic stores ptr to memory allocated by malloc with exactly
// CON_PEER_TOPIC_MEM_LEN bytes.
void init_peer(struct con_peer *p) __attribute__((nonnull));

// Sets attributes of conn_peer struct. topic is copied by strcpy and MUST be
// NULL terminated C string. Caller is responsible that topic is NOT greater
// than memory allocated by init_peer().
// NOTE: that is achived by fact that messages with topic longer than
// ZMQ_MAX_TOPIC_LEN are NOT allowed thus are never inserted in the list
void set_peer(struct con_peer *p, int fd, char *topic)
__attribute__((nonnull));

// If p is not NULL frees memory allocated by init_peer().
void destroy_peer(struct con_peer *p) __attribute__((nonnull));

// Initializes statically or dynamically allocated con_peer_list struct.
// Allocates memory for CON_PEER_LIST_DEFAULT_LEN of peers and initialize
// all the peers.
void init_con_peer_list(struct con_peer_list *list) __attribute__((nonnull));

// Adds peer to the first free spot in the list. The free peer spot has fd == -1.
// If there is no free spot, more memory is allocated for the new peers.
// Caller is responsible to assure that each added peer has an unique fd.
// The peers are uniquely identified by fd e.g. for the delete operation.
// It copies topic with given len to internal peer struct. It MUST be NULL
// terminated C string
void add_peer(struct con_peer_list *list, int fd, char *topic)
__attribute__((nonnull));

// Deletes the first peer with given fd in the list by setting the fd to -1.
void del_peer(struct con_peer_list *list, int fd) __attribute__((nonnull));

// Calls destroy_peer() on all the peers in the list.
void destroy_con_peer_list(struct con_peer_list *list);

#endif /*__SENTINEL_PROXY_CON_PEER_LIST_H__*/
