/* Copyright (c) 2013, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/qmi_encdec.h>
#include <mach/msm_qmi_interface.h>
#include "heap_mem_ext_v01.h"

struct elem_info mem_alloc_req_msg_data_v01_ei[] = {
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(uint32_t),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x01,
		.offset         = offsetof(struct mem_alloc_req_msg_v01,
					num_bytes),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(uint8_t),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(struct mem_alloc_req_msg_v01,
					block_alignment_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(uint32_t),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(struct mem_alloc_req_msg_v01,
					block_alignment),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type       = QMI_COMMON_TLV_TYPE,
	},
};

struct elem_info mem_alloc_resp_msg_data_v01_ei[] = {
	{
		.data_type      = QMI_SIGNED_2_BYTE_ENUM,
		.elem_len       = 1,
		.elem_size      = sizeof(uint16_t),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x01,
		.offset         = offsetof(struct mem_alloc_resp_msg_v01,
					resp),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(uint8_t),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(struct mem_alloc_resp_msg_v01,
					handle_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_8_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(uint64_t),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(struct mem_alloc_resp_msg_v01,
					handle),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(uint8_t),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x11,
		.offset         = offsetof(struct mem_alloc_resp_msg_v01,
					num_bytes_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(uint32_t),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x11,
		.offset         = offsetof(struct mem_alloc_resp_msg_v01,
					num_bytes),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type       = QMI_COMMON_TLV_TYPE,
	},
};

struct elem_info mem_free_req_msg_data_v01_ei[] = {
	{
		.data_type      = QMI_UNSIGNED_8_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(uint64_t),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x01,
		.offset         = offsetof(struct mem_free_req_msg_v01,
					handle),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type       = QMI_COMMON_TLV_TYPE,
	},
};

struct elem_info mem_free_resp_msg_data_v01_ei[] = {
	{
		.data_type      = QMI_SIGNED_2_BYTE_ENUM,
		.elem_len       = 1,
		.elem_size      = sizeof(uint16_t),
		.is_array       = NO_ARRAY,
		.tlv_type       = 0x01,
		.offset         = offsetof(struct mem_free_resp_msg_v01,
					resp),
	},
	{
		.data_type      = QMI_EOTI,
		.is_array       = NO_ARRAY,
		.tlv_type       = QMI_COMMON_TLV_TYPE,
	},
};
