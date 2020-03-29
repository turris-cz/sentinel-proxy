/*
 *  Turris:Sentinel Proxy - Main MQTT gateway to Sentinel infrastructure
 *  Copyright (C) 2020 CZ.NIC z.s.p.o. (https://www.nic.cz/)
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

#ifndef __SENTINEL_PROXY_DEVICE_TOKEN_H__
#define __SENTINEL_PROXY_DEVICE_TOKEN_H__
#include <stdbool.h>

#define DEVICE_TOKEN_LEN 64

enum dt_state {
    DT_OK,
    DT_UNDEF,  // device token not provided
    DT_LENGTH,  // token length does not match
    DT_DECODE,  // failure in decoding token
    DT_CRC,  // token crc does not match
    DT_NUM_STATES,  // guard value
};

/*
 * Return message describing provided state.
 */ 
const char *device_token_state_msg(enum dt_state state);

/*
 * Generate DEVICE_TOKEN_LEN hexachars long string with embedded CRC.
 * On success return the string, otherwise return NULL.
 */
char *device_token_generate() __attribute__((malloc));

/*
 * Verify device_token format and CRC. Return dt_state code which
 * equals DT_OK on success or one of the error codes otherwise.
 * device_token is supposed to be DEVICE_TOKEN_LEN hexachars long
 * string with embedded CRC.
 */
enum dt_state device_token_verify(const char *device_token);

#endif /*__SENTINEL_PROXY_DEVICE_TOKEN_H__*/
