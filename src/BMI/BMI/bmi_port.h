/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef _BMI_PORT_
#define _BMI_PORT_

#include <stdbool.h>
#include <stdint.h>
#include "bm/bm_sim/packet_handler.h"

// Converted this code from C to C++ so we have to use extern C to ensures a C++ function adheres to the C calling convention.
extern "C" {

typedef struct bmi_port_s bmi_port_t;

typedef struct bmi_port_mgr_s bmi_port_mgr_t;

typedef struct bmi_port_stats_s {
  uint64_t in_packets;
  uint64_t in_octets;
  uint64_t out_packets;
  uint64_t out_octets;
} bmi_port_stats_t;

/* the client must make a copy of the buffer memory, this memory cannot be
   modified and is no longer garanteed to be valid after the function
   returns. */
typedef void (*bmi_packet_handler_t)(int port_num, const char *buffer, int len, void *cookie);

int bmi_port_create_mgr(bmi_port_mgr_t **port_mgr, int max_port_count);

/* Start running the port manager on its own thread */
int bmi_start_mgr(bmi_port_mgr_t *port_mgr);

// int bmi_set_packet_handler(bmi_port_mgr_t *port_mgr,
// 			   bmi_packet_handler_t packet_handler,
// 			   void *cookie);

uint64_t get_truncated_timestamp_ns();

uint64_t truncated_timestamp_add_offset(uint64_t timestamp_ns, int64_t offset_us);

int bmi_set_packet_handler(bmi_port_mgr_t *port_mgr,
                                       const PacketHandlerWithPacketInfo &handler);
int bmi_set_packet_handler_with_packet_info(bmi_port_mgr_t *port_mgr,
                                       const PacketHandlerWithPacketInfo &handler);

int bmi_port_send(bmi_port_mgr_t *port_mgr,
		  int port_num, const char *buffer, int len);

int bmi_port_interface_add(bmi_port_mgr_t *port_mgr,
			   const char *ifname, int port_num,
			   const char *pcap_input_dump,
			   const char *pcap_output_dump);

int bmi_port_interface_remove(bmi_port_mgr_t *port_mgr, int port_num);

int bmi_port_destroy_mgr(bmi_port_mgr_t *port_mgr);

int bmi_port_interface_is_up(bmi_port_mgr_t *port_mgr,
                             int port_num,
                             bool *is_up);

int bmi_port_get_stats(bmi_port_mgr_t *port_mgr,
                       int port_num,
                       bmi_port_stats_t *port_stats);

/* use port_stats == NULL if you are not interested in the stats value before
   the clear */
int bmi_port_clear_stats(bmi_port_mgr_t *port_mgr,
                         int port_num,
                         bmi_port_stats_t *port_stats);

#endif

} //extern c