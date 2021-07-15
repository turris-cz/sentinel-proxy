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
#ifndef __SENTINEL_PROXY_LAST_MSG_LIST_H__
#define __SENTINEL_PROXY_LAST_MSG_LIST_H__

#include "common.h"

#define LAST_MSG_TOPIC_MEM_LEN (ZMQ_MAX_TOPIC_LEN + 1)
#define LAST_MSG_LIST_DEFAULT_LEN 4

struct last_msg {
	unsigned long long time_stamp;
	char *topic;
};

struct last_msg_list {
	size_t alloc_size;
	struct last_msg *messages;
};

// Initializes statically or dynamically allocated last_msg struct.
// time_stamp is set to 0. topic stores ptr to memory allocated by malloc with
// exactly LAST_MSG_TOPIC_MEM_LEN bytes. DOES assert check for msg.
void init_last_msg(struct last_msg *msg);

// Sets attributes of last_msg struct. topic is copied by memcpy and NULL
// string terminating char is put at topic[topic_len]. Caller is responsible
// that topic_len is NOT greater than memory allocated by init_last_msg().
// DOES assert check for msg and topic.
void set_last_msg(struct last_msg *msg, unsigned long long ts, char *topic,
	size_t topic_len);

// If msg is not NULL frees memory allocated by init_last_msg().
void destroy_last_msg(struct last_msg *msg);

// Initializes statically or dynamically allocated last_msg_list struct.
// Allocates memory for LAST_MSG_LIST_DEFAULT_LEN of last messages and initialize
// all of them. DOES assert check for list.
void init_last_msg_list(struct last_msg_list *list);

// Updates time_stamp of first last_msg in the list matching given topic.
// Each last_msg is uniquelly identified by topic. If there is no last_msg with
// given topic it is inserted in the list with given time_stamp. If there is no
// free spot in the list, more memory is allocated - the list doubles its size. 
// It copies topic with given len to internal last_msg struct.
// It puts NULL string terminating char at the end of topic.
// DOES assert check for list and topic.
void update_last_msg(struct last_msg_list *list, char *topic, size_t topic_len,
	unsigned long long ts);

// Calls destroy_last_msg() on all last_msg structs in the list.
// DOES assert check for list.
void destroy_last_msg_list(struct last_msg_list *list);

#endif /*__SENTINEL_PROXY_LAST_MSG_LIST_H__*/
