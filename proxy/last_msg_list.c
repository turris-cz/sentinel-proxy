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

#include "last_msg_list.h"
#include "log.h"

void init_last_msg(struct last_msg *msg) {
	TRACE_FUNC;
	assert(msg);
	msg->time_stamp = 0;
	msg->topic = malloc(LAST_MSG_TOPIC_MEM_LEN * sizeof(*msg->topic));
	msg->topic[0] = '\0';
}

void set_last_msg(struct last_msg *msg, unsigned long long ts, char *topic,
	size_t topic_len) {
	TRACE_FUNC;
	assert(msg);
	assert(topic);
	msg->time_stamp = ts;
	memcpy(msg->topic, topic, topic_len);
	msg->topic[topic_len] = '\0';
}

void destroy_last_msg(struct last_msg *msg) {
	TRACE_FUNC;
	if(msg)
		free(msg->topic);
}

void init_last_msg_list(struct last_msg_list *list) {
	TRACE_FUNC;
	assert(list);
	list->alloc_size = LAST_MSG_LIST_DEFAULT_LEN;
	list->messages = malloc(list->alloc_size * sizeof(*list->messages));
	for(size_t i = 0; i < list->alloc_size; i++)
		init_last_msg(&list->messages[i]);
}

void update_last_msg(struct last_msg_list *list, char *topic, size_t topic_len,
	unsigned long long ts) {
	TRACE_FUNC;
	assert(list);
	assert(topic);
	bool updated = false;
	for (size_t i = 0; i < list->alloc_size; i++) {
		if (list->messages[i].topic[0] == '\0') {
			// Last messages are added to list in sequence manner. If this
			// message has empty topic all the following have them empty as well.
			set_last_msg(&list->messages[i], ts, topic, topic_len);
			updated = true;
			break;
		}
		if (!strncmp(topic, list->messages[i].topic, topic_len)) {
			// If the message with known topic was received we only update time stamp
			list->messages[i].time_stamp = ts;
			updated = true;
			break;
		}
	}
	if (!updated) {
		size_t old_size = list->alloc_size;
		list->alloc_size *= 2;
		list->messages = realloc(list->messages, list->alloc_size
			* sizeof(*list->messages));
		for(size_t i = old_size; i < list->alloc_size; i++)
			init_last_msg(&list->messages[i]);
		set_last_msg(&list->messages[old_size], ts, topic, topic_len);
	}
}

void destroy_last_msg_list(struct last_msg_list *list) {
	TRACE_FUNC;
	if(list) {
		for(size_t i = 0; i < list->alloc_size; i++)
			destroy_last_msg(&list->messages[i]);
		free(list->messages);
	}
}
