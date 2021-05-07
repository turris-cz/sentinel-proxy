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

#define CON_PER_TOPIC_MEM_LEN (ZMQ_MAX_TOPIC_LEN + 1)
#define CON_PERR_LIST_DEFAULT_LEN 4

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
// ZMQ_MAX_TOPIC_LEN bytes.
// DOES assert check for p.
void init_peer(struct con_peer *p);

// Sets attributes of conn_peer struct. topic is copied by memcpy and NULL
// string terminating char is put at topic[topic_len]. Caller is responsible
// that topic_len is NOT greater than memory allocated by init_peer().
// DOES assert check for p and topic.
void set_peer(struct con_peer *p, int fd, char *topic, size_t topic_len);

// If p is not NULL frees memory allocated by init_peer().
void destroy_peer(struct con_peer *p);

// Initializes statically or dynamically allocated con_peer_list struct.
// Allocates memory for CON_PERR_LIST_DEFAULT_LEN of peers and initialize
// all the peers.
// DOES assert check for list.
void init_con_peer_list(struct con_peer_list *list);

// Adds peer to the first free spot in the list. The free peer spot has fd == -1.
// If there is no free spot, more memory is allocated for the new peers.
// Caller is responsible to assure that each added peer has an unique fd.
// The peers are uniquely identified by fd e.g. for the delete operation.
// It copies topic with given len to internal peer struct.
// It puts NULL string terminating char at the end of topic.
// DOES assert check for list and topic.
void add_peer(struct con_peer_list *list, int fd, char *topic, size_t topic_len);

// Deletes the first peer with given fd in the list by setting the fd to -1.
// DOES assert check for list.
void del_peer(struct con_peer_list *list, int fd);

// Calls destroy_peer() on all the peers in the list.
// DOES assert check for list.
void destroy_con_peer_list(struct con_peer_list *list);

#endif /*__SENTINEL_PROXY_CON_PEER_LIST_H__*/
