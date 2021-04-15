/*
 *  Turris:Sentinel Proxy - Main MQTT gateway to Sentinel infrastructure
 *  Copyright (C) 2018-2021 CZ.NIC z.s.p.o. (https://www.nic.cz/)
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
#ifndef __SENTINEL_PROXY_LOG_H__
#define __SENTINEL_PROXY_LOG_H__

#define DEFLOG log_sentinel_proxy // use our log as default one in logc macros

#include <logc.h>
#include <logc_util.h>

#define TRACE_FUNC TRACE(__func__)

extern log_t log_sentinel_proxy;

#endif /*__SENTINEL_PROXY_LOG_H__*/

