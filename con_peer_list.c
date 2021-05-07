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

#include "con_peer_list.h"
#include "log.h"

void init_peer(struct con_peer *p) {
	TRACE_FUNC;
	assert(p);
	p->fd = -1;
	p->topic = malloc(CON_PER_TOPIC_MEM_LEN * sizeof(*p->topic));
}

void set_peer(struct con_peer *p, int fd, char *topic, size_t topic_len) {
	TRACE_FUNC;
	assert(p);
	assert(topic);
	p->fd = fd;
	memcpy(p->topic, topic, topic_len);
	p->topic[topic_len] = '\0';
}

void destroy_peer(struct con_peer *p) {
	TRACE_FUNC;
	if (p)
		free(p->topic);
}

void init_con_peer_list(struct con_peer_list *list) {
	TRACE_FUNC;
	assert(list);
	list->alloc_size = CON_PERR_LIST_DEFAULT_LEN;
	list->peers = malloc(list->alloc_size * sizeof(*list->peers));
	for (size_t i = 0; i < list->alloc_size; i++)
		init_peer(&list->peers[i]);
}

void add_peer(struct con_peer_list *list, int fd, char *topic, size_t topic_len) {
	TRACE_FUNC;
	assert(list);
	assert(topic);
	bool added = false;
	for (size_t i = 0; i < list->alloc_size; i++)
		if (list->peers[i].fd == -1) {
			set_peer(&list->peers[i], fd, topic, topic_len);
			info("Connected peer with topic %s and session ID %d", topic, fd);
			added = true;
			break;
		}
	if (!added) {
		size_t old_size = list->alloc_size;
		list->alloc_size *= 2;
		list->peers = realloc(list->peers, list->alloc_size
			* sizeof(*list->peers));
		for(size_t i = old_size; i < list->alloc_size; i++)
			init_peer(&list->peers[i]);
		set_peer(&list->peers[old_size], fd, topic, topic_len);
		info("Connected peer with topic %s and session ID %d", topic, fd);
	}

}

void del_peer(struct con_peer_list *list, int fd) {
	TRACE_FUNC;
	assert(list);
	for(size_t i = 0; i < list->alloc_size; i++) {
		if (list->peers[i].fd == fd) {
			info("Disconnected peer with topic %s and session ID %d",
				list->peers[i].topic, fd);
			list->peers[i].fd = -1;
			break;
		}
	}
}

void destroy_con_peer_list(struct con_peer_list *list) {
	TRACE_FUNC;
	if(list) {
		for(size_t i = 0; i < list->alloc_size; i++)
			destroy_peer(&list->peers[i]);
		free(list->peers);
	}
}
