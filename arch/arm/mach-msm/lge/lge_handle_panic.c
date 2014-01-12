/*
 * arch/arm/mach-msm/lge/lge_handle_panic.c
 *
 * Copyright (C) 2012 LGE, Inc
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/platform_device.h>
#include <linux/reboot.h>
#include <linux/io.h>
#include <linux/of_address.h>
#include <asm/setup.h>
#include <linux/init.h>
#include <mach/subsystem_restart.h>
#include <mach/msm_iomap.h>
#include <mach/lge_handle_panic.h>
#include <mach/board_lge.h>

#define PANIC_HANDLER_NAME        "panic-handler"

#define DLOAD_MODE_ADDR           0x0
#define UEFI_RAM_DUMP_MAGIC_ADDR  0xC
#define RAM_CONSOLE_ADDR_ADDR     0x24
#define RAM_CONSOLE_SIZE_ADDR     0x28
#define FB1_ADDR_ADDR             0x2C

#define RAM_CONSOLE_ADDR    (MSM_IMEM_BASE + RAM_CONSOLE_ADDR_ADDR)
#define RAM_CONSOLE_SIZE    (MSM_IMEM_BASE + RAM_CONSOLE_SIZE_ADDR)
#define FB1_ADDR            (MSM_IMEM_BASE + FB1_ADDR_ADDR)

static int dummy_arg;
void *restart_reason_addr;

static int subsys_crash_magic = 0x0;

int lge_set_magic_subsystem(const char *name, int type)
{
	const char *subsys_name[] = { "adsp", "mba", "modem", "wcnss" };
	int i = 0;

	if (!name)
		return -1;

	for (i = 0; i < ARRAY_SIZE(subsys_name); i++) {
		if (!strncmp(subsys_name[i], name, 40)) {
			subsys_crash_magic = LGE_RB_MAGIC | ((i+1) << 12)
				| type;
			break;
		}
	}

	return 0;
}
EXPORT_SYMBOL(lge_set_magic_subsystem);

void lge_set_fb1_addr(unsigned int addr)
{
}
EXPORT_SYMBOL(lge_set_fb1_addr);

void lge_set_restart_reason(unsigned int reason)
{
	if ((lge_get_laf_mode() == LGE_LAF_MODE_LAF)
			&& (reason != LAF_DLOAD_MODE))
		__raw_writel(LGE_RB_MAGIC | LGE_LAF_CRASH, restart_reason_addr);
	else
		__raw_writel(reason, restart_reason_addr);
}
EXPORT_SYMBOL(lge_set_restart_reason);

void lge_set_panic_reason(void)
{
	if (subsys_crash_magic == 0)
		lge_set_restart_reason(LGE_RB_MAGIC | LGE_ERR_KERN);
	else
		lge_set_restart_reason(subsys_crash_magic);
}
EXPORT_SYMBOL(lge_set_panic_reason);

static int gen_bug(const char *val, struct kernel_param *kp)
{
	BUG();
	return 0;
}
module_param_call(gen_bug, gen_bug, param_get_bool, &dummy_arg,
		S_IWUSR | S_IRUGO);

static int gen_panic(const char *val, struct kernel_param *kp)
{
	panic("generate test-panic");
	return 0;
}
module_param_call(gen_panic, gen_panic, param_get_bool, &dummy_arg,\
		S_IWUSR | S_IRUGO);

static int gen_adsp_panic(const char *val, struct kernel_param *kp)
{
	subsystem_restart("adsp");
	return 0;
}
module_param_call(gen_adsp_panic, gen_adsp_panic, param_get_bool, &dummy_arg,
		S_IWUSR | S_IRUGO);

static int gen_mba_panic(const char *val, struct kernel_param *kp)
{
	subsystem_restart("mba");
	return 0;
}
module_param_call(gen_mba_panic, gen_mba_panic, param_get_bool, &dummy_arg,
		S_IWUSR | S_IRUGO);

static int gen_modem_panic(const char *val, struct kernel_param *kp)
{
	subsystem_restart("modem");
	return 0;
}
module_param_call(gen_modem_panic, gen_modem_panic, param_get_bool, &dummy_arg,
		S_IWUSR | S_IRUGO);

static int gen_wcnss_panic(const char *val, struct kernel_param *kp)
{
	subsystem_restart("wcnss");
	return 0;
}
module_param_call(gen_wcnss_panic, gen_wcnss_panic, param_get_bool, &dummy_arg,
		S_IWUSR | S_IRUGO);

#define WDT0_RST        0x04
#define WDT0_EN         0x08
#define WDT0_BARK_TIME  0x10
#define WDT0_BITE_TIME  0x14
#if 0
extern void __iomem *msm_timer_get_timer0_base(void);

static int gen_wdt_bark(const char *val, struct kernel_param *kp)
{
	static void __iomem *msm_tmr0_base;
	msm_tmr0_base = msm_timer_get_timer0_base();

	__raw_writel(0, msm_tmr0_base + WDT0_EN);
	__raw_writel(1, msm_tmr0_base + WDT0_RST);
	__raw_writel(0x31F3, msm_tmr0_base + WDT0_BARK_TIME);
	__raw_writel(5 * 0x31F3, msm_tmr0_base + WDT0_BITE_TIME);
	__raw_writel(1, msm_tmr0_base + WDT0_EN);
	return 0;
}
module_param_call(gen_wdt_bark, gen_wdt_bark, param_get_bool,
		&dummy_arg, S_IWUSR | S_IRUGO);

static int gen_wdt_bite(const char *val, struct kernel_param *kp)
{
	static void __iomem *msm_tmr0_base;
	msm_tmr0_base = msm_timer_get_timer0_base();
	__raw_writel(0, msm_tmr0_base + WDT0_EN);
	__raw_writel(1, msm_tmr0_base + WDT0_RST);
	__raw_writel(5 * 0x31F3, msm_tmr0_base + WDT0_BARK_TIME);
	__raw_writel(0x31F3, msm_tmr0_base + WDT0_BITE_TIME);
	__raw_writel(1, msm_tmr0_base + WDT0_EN);
	return 0;
}
module_param_call(gen_wdt_bite, gen_wdt_bite, param_get_bool,
		&dummy_arg, S_IWUSR | S_IRUGO);
#endif
static int gen_bus_hang(const char *val, struct kernel_param *kp)
{
	static void __iomem *reserved;

	reserved = ioremap(0xFF000000 - 0x10, 0x10);
	__raw_writel(1, reserved);

	return 0;
}
module_param_call(gen_bus_hang, gen_bus_hang, param_get_bool,
		&dummy_arg, S_IWUSR | S_IRUGO);

extern void msm_disable_wdog_debug(void);
static int gen_hw_reset(const char *val, struct kernel_param *kp)
{
	static void __iomem *reserved;

	msm_disable_wdog_debug();
	reserved = ioremap(0xFF000000 - 0x10, 0x10);
	__raw_writel(1, reserved);

	return 0;
}
module_param_call(gen_hw_reset, gen_hw_reset, param_get_bool,
		&dummy_arg, S_IWUSR | S_IRUGO);

static int __init lge_panic_handler_probe(struct platform_device *pdev)
{
	int ret = 0;
  struct device_node *np;

  np = of_find_compatible_node(NULL, NULL, "qti,msm-imem-restart_reason");
  if (!np) {
    pr_err("unable to find DT imem restart reason node\n");
    return -ENODEV;
  }
  restart_reason_addr = of_iomap(np, 0);
  if (!restart_reason_addr) {
    pr_err("unable to map imem restart reason offset\n");
    return -ENOMEM;
  }

	return ret;
}

static int __exit lge_panic_handler_remove(struct platform_device *pdev)
{
	return 0;
}

static struct platform_driver panic_handler_driver __refdata = {
	.probe = lge_panic_handler_probe,
	.remove = __exit_p(lge_panic_handler_remove),
	.driver = {
		.name = PANIC_HANDLER_NAME,
		.owner = THIS_MODULE,
	},
};

static int __init lge_panic_handler_init(void)
{
	return platform_driver_register(&panic_handler_driver);
}

static void __exit lge_panic_handler_exit(void)
{
	platform_driver_unregister(&panic_handler_driver);
}

module_init(lge_panic_handler_init);
module_exit(lge_panic_handler_exit);

MODULE_DESCRIPTION("LGE panic handler driver");
MODULE_AUTHOR("SungEun Kim <cleaneye.kim@lge.com>");
MODULE_LICENSE("GPL");
