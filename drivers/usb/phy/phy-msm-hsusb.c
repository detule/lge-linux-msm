/*
 * Copyright (c) 2012-2013, The Linux Foundation. All rights reserved.
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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>
#include <linux/usb/phy.h>
#include <linux/usb/msm_hsusb.h>

static int override_phy_init;
module_param(override_phy_init, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(override_phy_init, "Override HSPHY Init Seq");

/* QSCRATCH register settings differ based on MSM core ver */
#define MSM_CORE_VER_120		0x10020061

/* QSCRATCH register offsets */
#define GENERAL_CFG_REG			(0x08)
#define HS_PHY_CTRL_REG			(0x10)
#define PARAMETER_OVERRIDE_X_REG	(0x14)
#define ALT_INTERRUPT_EN_REG		(0x20)
#define HS_PHY_IRQ_STAT_REG		(0x24)
#define HS_PHY_CTRL_COMMON_REG		(0xEC)	/* ver >= MSM_CORE_VER_120 */

/* GENERAL_CFG_REG bits */
#define SEC_UTMI_FREE_CLK_GFM_SEL1	(0x80)

/* HS_PHY_CTRL_REG bits */
#define RETENABLEN			BIT(1)
#define FSEL_MASK			(0x7 << 4)
#define FSEL_DEFAULT			(0x3 << 4)
#define CLAMP_EN_N			BIT(7)
#define OTGSESSVLD_HV_CLAMP_EN_N	BIT(8)
#define ID_HV_CLAMP_EN_N		BIT(9)
#define COMMONONN			BIT(11)
#define OTGDISABLE0			BIT(12)
#define VBUSVLDEXT0			BIT(13)
#define VBUSVLDEXTSEL0			BIT(14)
#define OTGSESSVLDHV_INTEN		BIT(15)
#define IDHV_INTEN			BIT(16)
#define DPSEHV_CLAMP_EN_N		BIT(17)
#define UTMI_OTG_VBUS_VALID		BIT(20)
#define USB2_UTMI_CLK_EN		BIT(21)
#define USB2_SUSPEND_N			BIT(22)
#define USB2_SUSPEND_N_SEL		BIT(23)
#define DMSEHV_CLAMP_EN_N		BIT(24)
#define CLAMP_MPM_DPSE_DMSE_EN_N	BIT(26)
/* Following exist only when core_ver >= MSM_CORE_VER_120 */
#define FREECLK_DIS_WHEN_SUSP		BIT(27)
#define SW_SESSVLD_SEL			BIT(28)
#define FREECLOCK_SEL			BIT(29)

/* HS_PHY_CTRL_COMMON_REG bits used when core_ver >= MSM_CORE_VER_120 */
#define COMMON_PLLBTUNE		BIT(15)
#define COMMON_CLKCORE			BIT(14)
#define COMMON_VBUSVLDEXTSEL0		BIT(12)
#define COMMON_OTGDISABLE0		BIT(11)
#define COMMON_OTGTUNE0_MASK		(0x7 << 8)
#define COMMON_OTGTUNE0_DEFAULT		(0x4 << 8)
#define COMMON_COMMONONN		BIT(7)
#define COMMON_FSEL			(0x7 << 4)
#define COMMON_RETENABLEN		BIT(3)

/* ALT_INTERRUPT_EN/HS_PHY_IRQ_STAT bits */
#define ACAINTEN			BIT(0)
#define DMINTEN				BIT(1)
#define DCDINTEN			BIT(1)
#define DPINTEN				BIT(3)
#define CHGDETINTEN			BIT(4)
#define RIDFLOATNINTEN			BIT(5)
#define DPSEHV_INTEN			BIT(6)
#define DMSEHV_INTEN			BIT(7)
#define DPSEHV_HI_INTEN			BIT(8)
#define DPSEHV_LO_INTEN			BIT(9)
#define DMSEHV_HI_INTEN			BIT(10)
#define DMSEHV_LO_INTEN			BIT(11)
#define LINESTATE_INTEN			BIT(12)
#define DPDMHV_INT_MASK			(0xFC0)
#define ALT_INTERRUPT_MASK		(0x1FFF)

#define TCSR_USB30_CONTROL		BIT(8)
#define TCSR_HSPHY_ARES			BIT(11)

#define USB_HSPHY_3P3_VOL_MIN			3050000 /* uV */
#define USB_HSPHY_3P3_VOL_MAX			3300000 /* uV */
#define USB_HSPHY_3P3_HPM_LOAD			16000	/* uA */

#define USB_HSPHY_1P8_VOL_MIN			1800000 /* uV */
#define USB_HSPHY_1P8_VOL_MAX			1800000 /* uV */
#define USB_HSPHY_1P8_HPM_LOAD			19000	/* uA */

struct msm_hsphy {
	struct usb_phy		phy;
	void __iomem		*base;
	void __iomem		*tcsr;
	int			hsphy_init_seq;
	bool			set_pllbtune;
	u32			core_ver;

	struct regulator	*vdd;
	struct regulator	*vdda33;
	struct regulator	*vdda18;
	int			vdd_levels[3]; /* none, low, high */
	bool			suspended;

	/* Using external VBUS/ID notification */
	bool			ext_vbus_id;
};

static int msm_hsusb_config_vdd(struct msm_hsphy *phy, int high)
{
	int min, ret;

	min = high ? 1 : 0; /* low or none? */
	ret = regulator_set_voltage(phy->vdd, phy->vdd_levels[min],
				    phy->vdd_levels[2]);
	if (ret) {
		dev_err(phy->phy.dev, "unable to set voltage for hsusb vdd\n");
		return ret;
	}

	dev_dbg(phy->phy.dev, "%s: min_vol:%d max_vol:%d\n", __func__,
		phy->vdd_levels[min], phy->vdd_levels[2]);

	return ret;
}

static int msm_hsusb_ldo_enable(struct msm_hsphy *phy, int on)
{
	int rc = 0;

	dev_dbg(phy->phy.dev, "reg (%s)\n", on ? "HPM" : "LPM");

	if (!on)
		goto disable_regulators;


	rc = regulator_set_optimum_mode(phy->vdda18, USB_HSPHY_1P8_HPM_LOAD);
	if (rc < 0) {
		dev_err(phy->phy.dev, "Unable to set HPM of vdda18\n");
		return rc;
	}

	rc = regulator_set_voltage(phy->vdda18, USB_HSPHY_1P8_VOL_MIN,
						USB_HSPHY_1P8_VOL_MAX);
	if (rc) {
		dev_err(phy->phy.dev, "unable to set voltage for vdda18\n");
		goto put_vdda18_lpm;
	}

	rc = regulator_enable(phy->vdda18);
	if (rc) {
		dev_err(phy->phy.dev, "Unable to enable vdda18\n");
		goto unset_vdda18;
	}

	rc = regulator_set_optimum_mode(phy->vdda33, USB_HSPHY_3P3_HPM_LOAD);
	if (rc < 0) {
		dev_err(phy->phy.dev, "Unable to set HPM of vdda33\n");
		goto disable_vdda18;
	}

	rc = regulator_set_voltage(phy->vdda33, USB_HSPHY_3P3_VOL_MIN,
						USB_HSPHY_3P3_VOL_MAX);
	if (rc) {
		dev_err(phy->phy.dev, "unable to set voltage for vdda33\n");
		goto put_vdda33_lpm;
	}

	rc = regulator_enable(phy->vdda33);
	if (rc) {
		dev_err(phy->phy.dev, "Unable to enable vdda33\n");
		goto unset_vdda33;
	}

	return 0;

disable_regulators:
	rc = regulator_disable(phy->vdda33);
	if (rc)
		dev_err(phy->phy.dev, "Unable to disable vdda33\n");

unset_vdda33:
	rc = regulator_set_voltage(phy->vdda33, 0, USB_HSPHY_3P3_VOL_MAX);
	if (rc)
		dev_err(phy->phy.dev, "unable to set voltage for vdda33\n");

put_vdda33_lpm:
	rc = regulator_set_optimum_mode(phy->vdda33, 0);
	if (rc < 0)
		dev_err(phy->phy.dev, "Unable to set LPM of vdda33\n");

disable_vdda18:
	rc = regulator_disable(phy->vdda18);
	if (rc)
		dev_err(phy->phy.dev, "Unable to disable vdda18\n");

unset_vdda18:
	rc = regulator_set_voltage(phy->vdda18, 0, USB_HSPHY_1P8_VOL_MAX);
	if (rc)
		dev_err(phy->phy.dev, "unable to set voltage for vdda18\n");

put_vdda18_lpm:
	rc = regulator_set_optimum_mode(phy->vdda18, 0);
	if (rc < 0)
		dev_err(phy->phy.dev, "Unable to set LPM of vdda18\n");

	return rc < 0 ? rc : 0;
}

static void msm_usb_write_readback(void *base, u32 offset,
					const u32 mask, u32 val)
{
	u32 write_val, tmp = readl_relaxed(base + offset);

	tmp &= ~mask;		/* retain other bits */
	write_val = tmp | val;

	writel_relaxed(write_val, base + offset);

	/* Read back to see if val was written */
	tmp = readl_relaxed(base + offset);
	tmp &= mask;		/* clear other bits */

	if (tmp != val)
		pr_err("%s: write: %x to QSCRATCH: %x FAILED\n",
			__func__, val, offset);
}

static int msm_hsphy_init(struct usb_phy *uphy)
{
	struct msm_hsphy *phy = container_of(uphy, struct msm_hsphy, phy);
	u32 val;

	if (phy->tcsr) {
		val = readl_relaxed(phy->tcsr);

		/* Assert/deassert TCSR Reset */
		writel_relaxed((val | TCSR_HSPHY_ARES), phy->tcsr);
		usleep(1000);
		writel_relaxed((val & ~TCSR_HSPHY_ARES), phy->tcsr);
	}

	/* different sequences based on core version */
	phy->core_ver = readl_relaxed(phy->base);

	/*
	 * HSPHY Initialization: Enable UTMI clock and clamp enable HVINTs,
	 * and disable RETENTION (power-on default is ENABLED)
	 */
	val = readl_relaxed(phy->base + HS_PHY_CTRL_REG);
	val |= (USB2_UTMI_CLK_EN | CLAMP_MPM_DPSE_DMSE_EN_N | RETENABLEN);

	if (uphy->flags & ENABLE_SECONDARY_PHY) {
		val &= ~(USB2_UTMI_CLK_EN | FREECLOCK_SEL);
		val |= FREECLK_DIS_WHEN_SUSP;
	}

	writel_relaxed(val, phy->base + HS_PHY_CTRL_REG);
	usleep_range(2000, 2200);

	if (uphy->flags & ENABLE_SECONDARY_PHY)
		msm_usb_write_readback(phy->base, GENERAL_CFG_REG,
					SEC_UTMI_FREE_CLK_GFM_SEL1,
					SEC_UTMI_FREE_CLK_GFM_SEL1);

	if (phy->core_ver >= MSM_CORE_VER_120) {
		if (phy->set_pllbtune) {
			val = readl_relaxed(phy->base + HS_PHY_CTRL_COMMON_REG);
			val |= COMMON_PLLBTUNE | COMMON_CLKCORE;
			val &= ~COMMON_FSEL;
			writel_relaxed(val, phy->base + HS_PHY_CTRL_COMMON_REG);
		} else {
			writel_relaxed(COMMON_OTGDISABLE0 |
				COMMON_OTGTUNE0_DEFAULT |
				COMMON_COMMONONN | FSEL_DEFAULT |
				COMMON_RETENABLEN,
				phy->base + HS_PHY_CTRL_COMMON_REG);
		}
	}

	/*
	 * write HSPHY init value to QSCRATCH reg to set HSPHY parameters like
	 * VBUS valid threshold, disconnect valid threshold, DC voltage level,
	 * preempasis and rise/fall time.
	 */
	if (override_phy_init)
		phy->hsphy_init_seq = override_phy_init;
	if (phy->hsphy_init_seq)
		msm_usb_write_readback(phy->base,
					PARAMETER_OVERRIDE_X_REG, 0x03FFFFFF,
					phy->hsphy_init_seq & 0x03FFFFFF);

	return 0;
}

static int msm_hsphy_set_suspend(struct usb_phy *uphy, int suspend)
{
	struct msm_hsphy *phy = container_of(uphy, struct msm_hsphy, phy);
	bool host = uphy->flags & PHY_HOST_MODE;
	bool chg_connected = uphy->flags & PHY_CHARGER_CONNECTED;

	if (!!suspend == phy->suspended) {
		dev_dbg(uphy->dev, "%s\n", suspend ? "already suspended"
						   : "already resumed");
		return 0;
	}

	if (suspend) {
		/* Clear interrupt latch register */
		writel_relaxed(ALT_INTERRUPT_MASK,
				phy->base + HS_PHY_IRQ_STAT_REG);

		if (host) {
			/* Enable DP and DM HV interrupts */
			if (phy->core_ver >= MSM_CORE_VER_120)
				msm_usb_write_readback(phy->base,
							ALT_INTERRUPT_EN_REG,
							LINESTATE_INTEN,
							LINESTATE_INTEN);
			else
				msm_usb_write_readback(phy->base,
							ALT_INTERRUPT_EN_REG,
							DPDMHV_INT_MASK,
							DPDMHV_INT_MASK);
			udelay(5);
		} else {
			/* set the following:
			 * OTGDISABLE0=1
			 * USB2_SUSPEND_N_SEL=1, USB2_SUSPEND_N=0
			 */
			msm_usb_write_readback(phy->base, HS_PHY_CTRL_REG,
					(OTGDISABLE0 | USB2_SUSPEND_N_SEL |
					 USB2_SUSPEND_N),
					(OTGDISABLE0 | USB2_SUSPEND_N_SEL));
			if (!chg_connected)
				/* Enable PHY retention */
				msm_usb_write_readback(phy->base,
							HS_PHY_CTRL_REG,
							RETENABLEN, 0);
		}

		if (!phy->ext_vbus_id)
			/* Enable PHY-based IDHV and OTGSESSVLD HV interrupts */
			msm_usb_write_readback(phy->base, HS_PHY_CTRL_REG,
					(OTGSESSVLDHV_INTEN | IDHV_INTEN),
					(OTGSESSVLDHV_INTEN | IDHV_INTEN));

		/* can turn off regulators if disconnected in device mode */
		if (!host && !chg_connected) {
			if (phy->ext_vbus_id)
				msm_hsusb_ldo_enable(phy, 0);
			msm_hsusb_config_vdd(phy, 0);
		}
	} else {
		if (!host && !chg_connected) {
			msm_hsusb_config_vdd(phy, 1);
			if (phy->ext_vbus_id)
				msm_hsusb_ldo_enable(phy, 1);
		}

		if (phy->core_ver >= MSM_CORE_VER_120)
			msm_usb_write_readback(phy->base,
						HS_PHY_CTRL_COMMON_REG,
						FSEL_MASK, FSEL_DEFAULT);

		if (!phy->ext_vbus_id)
			/* Disable HV interrupts */
			msm_usb_write_readback(phy->base, HS_PHY_CTRL_REG,
					(OTGSESSVLDHV_INTEN | IDHV_INTEN), 0);

		if (host) {
			/* Clear interrupt latch register */
			writel_relaxed(0x0, phy->base + HS_PHY_IRQ_STAT_REG);
			/* Disable DP and DM HV interrupt */
			if (phy->core_ver >= MSM_CORE_VER_120)
				msm_usb_write_readback(phy->base,
							ALT_INTERRUPT_EN_REG,
							LINESTATE_INTEN, 0);
			else
				msm_usb_write_readback(phy->base,
							ALT_INTERRUPT_EN_REG,
							DPDMHV_INT_MASK, 0);
		} else {
			/* Disable PHY retention */
			msm_usb_write_readback(phy->base, HS_PHY_CTRL_REG,
						RETENABLEN, RETENABLEN);
			/* Bring PHY out of suspend */
			msm_usb_write_readback(phy->base, HS_PHY_CTRL_REG,
						(OTGDISABLE0 |
						 USB2_SUSPEND_N_SEL |
						 USB2_SUSPEND_N),
						0);
		}
	}

	phy->suspended = !!suspend; /* double-NOT coerces to bool value */
	return 0;
}

static int msm_hsphy_notify_connect(struct usb_phy *uphy,
				    enum usb_device_speed speed)
{
	struct msm_hsphy *phy = container_of(uphy, struct msm_hsphy, phy);

	if (uphy->flags & PHY_HOST_MODE)
		return 0;

	if (!(uphy->flags & PHY_VBUS_VALID_OVERRIDE))
		return 0;

	/* Set External VBUS Valid Select. Set once, can be left on */
	if (phy->core_ver >= MSM_CORE_VER_120) {
		msm_usb_write_readback(phy->base, HS_PHY_CTRL_COMMON_REG,
					COMMON_VBUSVLDEXTSEL0,
					COMMON_VBUSVLDEXTSEL0);
	} else {
		msm_usb_write_readback(phy->base, HS_PHY_CTRL_REG,
					VBUSVLDEXTSEL0, VBUSVLDEXTSEL0);
	}

	/* Enable D+ pull-up resistor */
	msm_usb_write_readback(phy->base, HS_PHY_CTRL_REG,
				VBUSVLDEXT0, VBUSVLDEXT0);

	/* Set OTG VBUS Valid from HSPHY to controller */
	msm_usb_write_readback(phy->base, HS_PHY_CTRL_REG,
				UTMI_OTG_VBUS_VALID, UTMI_OTG_VBUS_VALID);

	/* Indicate value is driven by UTMI_OTG_VBUS_VALID bit */
	if (phy->core_ver >= MSM_CORE_VER_120)
		msm_usb_write_readback(phy->base, HS_PHY_CTRL_REG,
					SW_SESSVLD_SEL, SW_SESSVLD_SEL);

	return 0;
}

static int msm_hsphy_notify_disconnect(struct usb_phy *uphy,
				       enum usb_device_speed speed)
{
	struct msm_hsphy *phy = container_of(uphy, struct msm_hsphy, phy);

	if (uphy->flags & PHY_HOST_MODE)
		return 0;

	if (!(uphy->flags & PHY_VBUS_VALID_OVERRIDE))
		return 0;

	/* Clear OTG VBUS Valid to Controller */
	msm_usb_write_readback(phy->base, HS_PHY_CTRL_REG,
				UTMI_OTG_VBUS_VALID, 0);

	/* Disable D+ pull-up resistor */
	msm_usb_write_readback(phy->base, HS_PHY_CTRL_REG, VBUSVLDEXT0, 0);

	/* Indicate value is no longer driven by UTMI_OTG_VBUS_VALID bit */
	if (phy->core_ver >= MSM_CORE_VER_120)
		msm_usb_write_readback(phy->base, HS_PHY_CTRL_REG,
					SW_SESSVLD_SEL, 0);

	return 0;
}

static int msm_hsphy_probe(struct platform_device *pdev)
{
	struct msm_hsphy *phy;
	struct device *dev = &pdev->dev;
	struct resource *res;
	int ret = 0;

	phy = devm_kzalloc(dev, sizeof(*phy), GFP_KERNEL);
	if (!phy) {
		ret = -ENOMEM;
		goto err_ret;
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(dev, "missing memory base resource\n");
		ret = -ENODEV;
		goto err_ret;
	}

	phy->base = devm_ioremap_nocache(dev, res->start, resource_size(res));
	if (!phy->base) {
		dev_err(dev, "ioremap failed\n");
		ret = -ENODEV;
		goto err_ret;
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (res) {
		phy->tcsr = devm_ioremap_nocache(dev, res->start,
						 resource_size(res));
		if (!phy->tcsr) {
			dev_err(dev, "tcsr ioremap failed\n");
			return -ENODEV;
		}

		/* switch MUX to let SNPS controller use the primary HSPHY */
		writel_relaxed(readl_relaxed(phy->tcsr) | TCSR_USB30_CONTROL,
				phy->tcsr);
	}

	if (of_get_property(dev->of_node, "qcom,primary-phy", NULL)) {
		dev_dbg(dev, "secondary HSPHY\n");
		phy->phy.flags |= ENABLE_SECONDARY_PHY;
	}

	ret = of_property_read_u32_array(dev->of_node, "qcom,vdd-voltage-level",
					 (u32 *) phy->vdd_levels,
					 ARRAY_SIZE(phy->vdd_levels));
	if (ret) {
		dev_err(dev, "error reading qcom,vdd-voltage-level property\n");
		goto err_ret;
	}

	phy->ext_vbus_id = of_property_read_bool(dev->of_node,
						"qcom,ext-vbus-id");
	phy->phy.dev = dev;

	phy->vdd = devm_regulator_get(dev, "vdd");
	if (IS_ERR(phy->vdd)) {
		dev_err(dev, "unable to get vdd supply\n");
		ret = PTR_ERR(phy->vdd);
		goto err_ret;
	}

	phy->vdda33 = devm_regulator_get(dev, "vdda33");
	if (IS_ERR(phy->vdda33)) {
		dev_err(dev, "unable to get vdda33 supply\n");
		ret = PTR_ERR(phy->vdda33);
		goto err_ret;
	}

	phy->vdda18 = devm_regulator_get(dev, "vdda18");
	if (IS_ERR(phy->vdda18)) {
		dev_err(dev, "unable to get vdda18 supply\n");
		ret = PTR_ERR(phy->vdda18);
		goto err_ret;
	}

	ret = msm_hsusb_config_vdd(phy, 1);
	if (ret) {
		dev_err(dev, "hsusb vdd_dig configuration failed\n");
		goto err_ret;
	}

	ret = regulator_enable(phy->vdd);
	if (ret) {
		dev_err(dev, "unable to enable the hsusb vdd_dig\n");
		goto unconfig_hs_vdd;
	}

	ret = msm_hsusb_ldo_enable(phy, 1);
	if (ret) {
		dev_err(dev, "hsusb vreg enable failed\n");
		goto disable_hs_vdd;
	}

	if (of_property_read_u32(dev->of_node, "qcom,hsphy-init",
					&phy->hsphy_init_seq))
		dev_dbg(dev, "unable to read hsphy init seq\n");
	else if (!phy->hsphy_init_seq)
		dev_warn(dev, "hsphy init seq cannot be 0. Using POR value\n");

	phy->set_pllbtune = of_property_read_bool(dev->of_node,
						 "qcom,set-pllbtune");

	platform_set_drvdata(pdev, phy);

	if (of_property_read_bool(dev->of_node, "qcom,vbus-valid-override"))
		phy->phy.flags |= PHY_VBUS_VALID_OVERRIDE;

	phy->phy.init			= msm_hsphy_init;
	phy->phy.set_suspend		= msm_hsphy_set_suspend;
	phy->phy.notify_connect		= msm_hsphy_notify_connect;
	phy->phy.notify_disconnect	= msm_hsphy_notify_disconnect;
	/*FIXME: this conflicts with dwc3_otg */
	/*phy->phy.type			= USB_PHY_TYPE_USB2; */

	ret = usb_add_phy_dev(&phy->phy);
	if (ret)
		goto disable_hs_ldo;

	return 0;

disable_hs_ldo:
	msm_hsusb_ldo_enable(phy, 0);
disable_hs_vdd:
	regulator_disable(phy->vdd);
unconfig_hs_vdd:
	msm_hsusb_config_vdd(phy, 0);
err_ret:
	return ret;
}

static int msm_hsphy_remove(struct platform_device *pdev)
{
	struct msm_hsphy *phy = platform_get_drvdata(pdev);

	if (!phy)
		return 0;

	usb_remove_phy(&phy->phy);
	msm_hsusb_ldo_enable(phy, 0);
	regulator_disable(phy->vdd);
	msm_hsusb_config_vdd(phy, 0);
	kfree(phy);

	return 0;
}

static const struct of_device_id msm_usb_id_table[] = {
	{
		.compatible = "qcom,usb-hsphy",
	},
	{ },
};
MODULE_DEVICE_TABLE(of, msm_usb_id_table);

static struct platform_driver msm_hsphy_driver = {
	.probe		= msm_hsphy_probe,
	.remove		= msm_hsphy_remove,
	.driver = {
		.name	= "msm-usb-hsphy",
		.of_match_table = of_match_ptr(msm_usb_id_table),
	},
};

module_platform_driver(msm_hsphy_driver);

MODULE_DESCRIPTION("MSM USB HS PHY driver");
MODULE_LICENSE("GPL v2");
