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

#define pr_fmt(fmt)	"VPU, %s: " fmt, __func__

#include <linux/types.h>
#include <linux/clk.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <mach/msm_bus.h>

#include "vpu_bus_clock.h"
#include "vpu_resources.h"


struct vpu_bus_ctrl {
	u32 bus_client;
	struct bus_load_tbl *btabl;
};

static struct vpu_bus_ctrl g_vpu_bus_ctrl;

int vpu_bus_init(struct vpu_platform_resources *res)
{
	struct vpu_bus_ctrl *ctrl;
	int rc = 0;

	if (!res || res->bus_table.count == 0)
		return -EINVAL;

	ctrl = &g_vpu_bus_ctrl;
	ctrl->btabl = &res->bus_table;
	if (ctrl->bus_client)
		return 0;

	ctrl->bus_client = msm_bus_scale_register_client(&res->bus_pdata);
	if (!ctrl->bus_client) {
		pr_err("Failed to register bus scale client\n");
		goto err_init_bus;
	}

	return rc;

err_init_bus:
	vpu_bus_deinit();
	return -EINVAL;
}

void vpu_bus_deinit(void)
{
	struct vpu_bus_ctrl *ctrl = &g_vpu_bus_ctrl;

	if (ctrl->bus_client) {
		msm_bus_scale_unregister_client(ctrl->bus_client);
		ctrl->bus_client = 0;
	}
}

static int __get_bus_vector(struct vpu_bus_ctrl *ctrl, u32 load)
{
	int i, j;
	int num_rows = ctrl->btabl ? ctrl->btabl->count : 0;

	if (num_rows <= 1)
		return 0;

	for (i = 0; i < num_rows; i++) {
		if (load <= ctrl->btabl->loads[i])
			break;
	}

	j = (i < num_rows) ? i : num_rows - 1;

	pr_debug("Required bus = %d\n", j);
	return j;
}

int vpu_bus_vote(void)
{
	int rc = 0;
	u32 handle = 0;
	struct vpu_bus_ctrl *ctrl = &g_vpu_bus_ctrl;

	handle = ctrl->bus_client;
	if (handle) {
		rc = msm_bus_scale_client_update_request(
				handle, ctrl->btabl->count - 1);
		if (rc)
			pr_err("Failed to vote bus: %d\n", rc);
	}

	return rc;
}

int vpu_bus_unvote(void)
{
	int rc = 0;
	u32 handle = 0;
	struct vpu_bus_ctrl *ctrl = &g_vpu_bus_ctrl;

	handle = ctrl->bus_client;
	if (handle) {
		rc = msm_bus_scale_client_update_request(
				handle, 0);
		if (rc)
			pr_err("Failed to unvote bus: %d\n", rc);
	}

	return rc;
}

int vpu_bus_scale(u32 load)
{
	int rc = 0;
	u32 handle = 0;
	struct vpu_bus_ctrl *ctrl = &g_vpu_bus_ctrl;

	handle = ctrl->bus_client;
	if (handle) {
		rc = msm_bus_scale_client_update_request(
				handle, __get_bus_vector(ctrl, load));
		if (rc)
			pr_err("Failed to scale bus: %d\n", rc);
	}

	return rc;
}

/*
 * Here's the list of clks going into VPU:
 * clock name:			svs/nominal/turbo (MHz)
 * vpu_ahb_clk			40 / 80/ 80
 * vpu_axi_clk			150/333/466
 * vpu_bus_clk			40 / 80/ 80
 * vpu_maple_clk		200/400/400
 * vpu_vdp_clk			200/200/400
 * vpu_qdss_apb_clk
 * vpu_qdss_at_clk
 * vpu_qdss_tsctr_div8_clk
 * vpu_sleep_clk	qtimer when xo is disabled, watchdog
 * vpu_cxo_clk		qtimer in active mode

 * The vpu_ahb_clk, vpu_maple_axi_clk, and vpu_axi_clk will be
 * subject to DCD frequency changes.
 * There is a case where for power consumption we may wish to switch the
 * vpu_vdp_clk between 200MHz and 400MHz during runtime to optimize for
 * power consumption
 */
#define	VPU_CLK_GATE_LEVEL VPU_VDP_CLK

static const char *clock_names[VPU_MAX_CLKS] = {
	[VPU_BUS_CLK] = "vdp_bus_clk",
	[VPU_MAPLE_CLK] = "core_clk",
	[VPU_VDP_CLK] = "vdp_clk",
	[VPU_AHB_CLK] = "iface_clk",
	[VPU_AXI_CLK] = "bus_clk",
	[VPU_SLEEP_CLK] = "sleep_clk",
	[VPU_CXO_CLK] = "cxo_clk",
	[VPU_MAPLE_AXI_CLK] = "maple_bus_clk",
	[VPU_PRNG_CLK] = "prng_clk",
};

struct vpu_core_clock {
	struct clk *clk;
	u32 status;
	u32 current_freq;
	struct load_freq_table *load_freq_tbl;
	const char *name;
};

static const u32 clock_freqs[VPU_MAX_CLKS][VPU_POWER_MAX] = {
	[VPU_BUS_CLK]	= { 40000000,  80000000,  80000000},
	[VPU_MAPLE_CLK]	= {200000000, 400000000, 400000000},
	[VPU_VDP_CLK]	= {200000000, 200000000, 400000000},
};

/*
 * Note: there is no lock in this block
 * It is caller's responsibility to serialize the calls
 */
struct vpu_clk_control {
	u32 load;

	/* svs, nominal, turbo, dynamic(default) */
	u32 mode;

	struct vpu_core_clock clock[VPU_MAX_CLKS];
};

void *vpu_clock_init(struct vpu_platform_resources *res)
{
	int i;
	int rc = -1;
	struct vpu_core_clock *cl;
	struct vpu_clk_control *clk_ctrl;

	if (!res)
		return NULL;

	clk_ctrl = (struct vpu_clk_control *)
			kzalloc(sizeof(struct vpu_clk_control), GFP_KERNEL);
	if (!clk_ctrl) {
		pr_err("failed to allocate clock ctrl block\n");
		return NULL;
	}

	/* setup the clock handles */
	for (i = 0; i < VPU_MAX_CLKS; i++) {
		cl = &clk_ctrl->clock[i];

		cl->load_freq_tbl = &res->clock_tables[i];
		cl->name = clock_names[i];

		if (i <= VPU_CLK_GATE_LEVEL && cl->load_freq_tbl->count == 0) {
			pr_err("%s freq table size is 0\n", cl->name);
			goto fail_init_clocks;
		}

		cl->clk = devm_clk_get(&res->pdev->dev, cl->name);
		if (IS_ERR_OR_NULL(cl->clk)) {
			pr_err("Failed to get clock: %s\n", cl->name);
			rc = PTR_ERR(cl->clk);
			break;
		}
		cl->status = 0;
	}

	/* free the clock if not all successful */
	if (i < VPU_MAX_CLKS) {
		for (i = 0; i < VPU_MAX_CLKS; i++) {
			cl = &clk_ctrl->clock[i];
			if (cl->clk) {
				clk_put(cl->clk);
				cl->clk = NULL;
			}
		}
		goto fail_init_clocks;
	}

	return clk_ctrl;

fail_init_clocks:
	kfree(clk_ctrl);
	return NULL;
}

void vpu_clock_deinit(void *clkh)
{
	int i;
	struct vpu_core_clock *cl;
	struct vpu_clk_control *clk_ctr = (struct vpu_clk_control *)clkh;

	if (!clk_ctr) {
		pr_err("Invalid param\n");
		return;
	}

	for (i = 0; i < VPU_MAX_CLKS; i++) {
		cl = &clk_ctr->clock[i];
		if (cl->status) {
			clk_disable_unprepare(cl->clk);
			cl->status = 0;
		}
		clk_put(cl->clk);
		cl->clk = NULL;
	}

	kfree(clk_ctr);
}

int vpu_clock_enable(void *clkh)
{
	struct vpu_core_clock *cl;
	struct vpu_clk_control *clk_ctr = (struct vpu_clk_control *)clkh;
	int i = 0;
	int rc = 0;

	if (!clk_ctr) {
		pr_err("Invalid param: %p\n", clk_ctr);
		return -EINVAL;
	}

	clk_ctr->mode = VPU_POWER_DYNAMIC;

	for (i = 0; i < VPU_MAX_CLKS; i++) {
		cl = &clk_ctr->clock[i];

		if (cl->status == 0) {
			/* set rate if it's a gated clock */
			if (i <= VPU_CLK_GATE_LEVEL &&
				cl->load_freq_tbl->entry) {
				cl->current_freq =
					cl->load_freq_tbl->entry[0].freq;

				rc = clk_set_rate(cl->clk, cl->current_freq);
				if (rc) {
					pr_err("Failed to set rate for %s\n",
						cl->name);
					goto fail_clk_enable;
				}
			}

			rc = clk_prepare_enable(cl->clk);
			if (rc) {
				pr_err("Failed to enable clock %s (err %d)\n",
						cl->name, rc);
				goto fail_clk_enable;
			} else {
				pr_debug("%s prepare_enabled\n", cl->name);
				cl->status = 1;
			}
		}
	}

	return rc;

fail_clk_enable:
	for (i = 0; i < VPU_MAX_CLKS; i++) {
		cl = &clk_ctr->clock[i];
		if (cl->status) {
			clk_disable_unprepare(cl->clk);
			cl->status = 0;
		}
	}

	return rc;
}

void vpu_clock_disable(void *clkh)
{
	int i;
	struct vpu_core_clock *cl;
	struct vpu_clk_control *clk_ctr = (struct vpu_clk_control *)clkh;

	if (!clk_ctr) {
		pr_err("Invalid param: %p\n", clk_ctr);
		return;
	}

	for (i = 0; i < VPU_MAX_CLKS; i++) {
		cl = &clk_ctr->clock[i];
		if (cl->status) {
			clk_disable_unprepare(cl->clk);
			cl->status = 0;
		}
	}
}

static unsigned long __clock_get_rate(struct vpu_core_clock *clock,
	u32 num_bits_per_sec)
{
	struct load_freq_table *table = clock->load_freq_tbl;
	unsigned long ret = 0;
	int i;

	for (i = 0; i < table->count; i++) {
		ret = table->entry[i].freq;
		if (num_bits_per_sec <= table->entry[i].load)
			break;
	}

	pr_debug("Required clock rate = %lu\n", ret);
	return ret;
}

int vpu_clock_scale(void *clkh, u32 load)
{
	struct vpu_clk_control *clk_ctr = (struct vpu_clk_control *)clkh;
	int i, rc = 0;

	if (!clk_ctr) {
		pr_err("Invalid param: %p\n", clk_ctr);
		return -EINVAL;
	}

	clk_ctr->load = load;

	for (i = 0; i <= VPU_CLK_GATE_LEVEL; i++) {
		struct vpu_core_clock *cl = &clk_ctr->clock[i];
		unsigned long freq;

		freq = __clock_get_rate(cl, load);
		if (clk_ctr->mode == VPU_POWER_DYNAMIC) {
			rc = clk_set_rate(cl->clk, freq);
			if (rc) {
				pr_err("clk_set_rate failed %s rate: %lu\n",
						cl->name, freq);
				break;
			}
		}
		cl->current_freq = freq;
	}

	return rc;
}

int vpu_clock_gating_off(void *clkh)
{
	int i;
	struct vpu_core_clock *cl;
	struct vpu_clk_control *clk_ctr = (struct vpu_clk_control *)clkh;
	int rc = 0;

	if (!clk_ctr) {
		pr_err("Invalid param: %p\n", clk_ctr);
		return -EINVAL;
	}

	/* no change if in manual mode */
	if (clk_ctr->mode != VPU_POWER_DYNAMIC)
		return 0;

	for (i = 0; i <= VPU_CLK_GATE_LEVEL; i++) {
		cl = &clk_ctr->clock[i];
		if (cl->status == 0) {
			rc = clk_enable(cl->clk);
			if (rc) {
				pr_err("Failed to enable %s\n", cl->name);
				break;
			} else {
				cl->status = 1;
				pr_debug("%s enabled\n", cl->name);
			}
		}
	}

	return rc;
}

void vpu_clock_gating_on(void *clkh)
{
	int i;
	struct vpu_core_clock *cl;
	struct vpu_clk_control *clk_ctr = (struct vpu_clk_control *)clkh;

	if (!clk_ctr) {
		pr_err("Invalid param: %p\n", clk_ctr);
		return;
	}

	/* no change if in manual mode */
	if (clk_ctr->mode != VPU_POWER_DYNAMIC)
		return;

	for (i = 0; i <= VPU_CLK_GATE_LEVEL; i++) {
		cl = &clk_ctr->clock[i];
		if (cl->status) {
			clk_disable(cl->clk);
			cl->status = 0;
		}
	}

	return;
}

void vpu_clock_mode_set(void *clkh, enum vpu_power_mode mode)
{
	struct vpu_clk_control *clk_ctr = (struct vpu_clk_control *)clkh;
	int i, rc = 0;

	if (!clk_ctr)
		return;

	/* no need to do anything if no change */
	if (mode == clk_ctr->mode)
		return;

	if (mode <= VPU_POWER_DYNAMIC) {
		clk_ctr->mode = mode;
		for (i = 0; i <= VPU_CLK_GATE_LEVEL; i++) {
			struct vpu_core_clock *cl = &clk_ctr->clock[i];
			unsigned long freq;

			if (mode < VPU_POWER_DYNAMIC)
				freq = clock_freqs[i][mode];
			else
				freq = cl->current_freq;

			rc = clk_set_rate(cl->clk, freq);

			if (rc)
				pr_err("clk_set_rate failed %s rate: %lu\n",
						cl->name, freq);
		}
	}
}

enum vpu_power_mode vpu_clock_mode_get(void *clkh)
{
	struct vpu_clk_control *clk_ctr = (struct vpu_clk_control *)clkh;

	if (!clk_ctr)
		return 0;
	else
		return clk_ctr->mode;
}

