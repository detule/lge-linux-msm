ifeq ($(CONFIG_OF),y)

dtb-$(CONFIG_ARCH_MSM8974) += msm8974-v1-cdp.dtb \
	msm8974-v1-fluid.dtb \
	msm8974-v1-liquid.dtb \
	msm8974-v1-mtp.dtb \
	msm8974-v1-rumi.dtb \
	msm8974-v1-sim.dtb \
	msm8974-v2.0-1-cdp.dtb \
	msm8974-v2.0-1-fluid.dtb \
	msm8974-v2.0-1-liquid.dtb \
	msm8974-v2.0-1-mtp.dtb \
	apq8074-v2.0-1-cdp.dtb \
	apq8074-v2.0-1-liquid.dtb \
	apq8074-v2.0-1-dragonboard.dtb \
	apq8074-v2.2-cdp.dtb \
	apq8074-v2.2-liquid.dtb \
	apq8074-v2.2-dragonboard.dtb \
	msm8974-v2.2-cdp.dtb \
	msm8974-v2.2-fluid.dtb \
	msm8974-v2.2-liquid.dtb \
	msm8974-v2.2-mtp.dtb \
	msm8974pro-ab-pm8941-cdp.dtb \
	msm8974pro-ab-pm8941-fluid.dtb \
	msm8974pro-ab-pm8941-liquid.dtb \
	msm8974pro-ab-pm8941-mtp.dtb \
	msm8974pro-ac-pm8941-cdp.dtb \
	msm8974pro-ac-pm8941-liquid.dtb \
	msm8974pro-ac-pm8941-mtp.dtb \
	msm8974pro-ac-pma8084-pm8941-mtp.dtb
dtb-$(CONFIG_ARCH_MSM8226) += msm8226-sim.dtb \
	msm8226-fluid.dtb \
	msm8226-v1-cdp.dtb \
	msm8226-v1-mtp.dtb \
	msm8226-v1-qrd-evt.dtb \
	msm8226-v1-qrd-dvt.dtb \
	msm8226-v2-720p-cdp.dtb \
	msm8226-v2-1080p-cdp.dtb \
	msm8226-v2-720p-mtp.dtb \
	msm8226-v2-1080p-mtp.dtb \
	msm8226-v2-qrd-evt.dtb \
	msm8226-v2-qrd-dvt.dtb \
	msm8926-720p-cdp.dtb \
	msm8926-1080p-cdp.dtb \
	msm8926-720p-mtp.dtb \
	msm8926-1080p-mtp.dtb \
	msm8926-qrd.dtb \
	msm8926-qrd-skug.dtb \
	msm8926-qrd-skug-pvt.dtb \
	msm8226-v1-qrd-skuf.dtb \
	msm8226-v2-qrd-skuf.dtb \
	apq8026-v1-xpm.dtb \
	apq8026-v1-cdp.dtb \
	apq8026-v1-mtp.dtb \
	apq8026-v2-xpm.dtb \
	apq8026-v2-720p-cdp.dtb \
	apq8026-v2-1080p-cdp.dtb \
	apq8026-v2-720p-mtp.dtb \
	apq8026-v2-1080p-mtp.dtb
dtb-$(CONFIG_ARCH_MSM8610) += msm8610-rumi.dtb \
	msm8610-v1-cdp.dtb \
	msm8610-v2-cdp.dtb \
	msm8610-v1-mtp.dtb \
	msm8610-v2-mtp.dtb \
	msm8610-sim.dtb \
	msm8610-v1-qrd-skuaa.dtb \
	msm8610-v1-qrd-skuab.dtb \
	msm8610-v2-qrd-skuaa.dtb \
	msm8610-v2-qrd-skuab.dtb
dtb-$(CONFIG_ARCH_FSM9900) += fsm9900-rumi.dtb \
	fsm9900-sim.dtb \
	fsm9900-cdp.dtb \
	fsm9900-mtp.dtb
dtb-$(CONFIG_ARCH_MSMKRYPTON) += msmkrypton-sim.dtb \
	msmkrypton-cdp.dtb \
	msmkrypton-mtp.dtb
dtb-$(CONFIG_ARCH_MSMSAMARIUM) += msmsamarium-sim.dtb \
	msmsamarium-rumi.dtb \
	msmsamarium-cdp-interposer.dtb \
	msmsamarium-cdp.dtb \
	msmsamarium-mtp.dtb \
	apqsamarium-mtp.dtb
dtb-$(CONFIG_ARCH_MPQ8092) += mpq8092-sim.dtb \
	mpq8092-rumi.dtb \
	mpq8092-cdp.dtb \
	mpq8092-dtv.dtb \
	mpq8092-dma.dtb
dtb-$(CONFIG_ARCH_APQ8084) += apq8084-sim.dtb \
	apq8084-interposer-cdp.dtb \
	apq8084-liquid.dtb \
	apq8084-smb1357-cdp.dtb \
	apq8084-smb1357-mtp.dtb \
	apq8084-smb1359-mtp.dtb \
	apq8084-smb349-cdp.dtb \
	apq8084-smb349-mtp.dtb \
	apq8084-sbc.dtb

DTB_NAMES := $(subst $\",,$(CONFIG_BUILD_ARM_APPENDED_DTB_IMAGE_NAMES))
ifneq ($(DTB_NAMES),)
DTB_LIST := $(addsuffix .dtb,$(DTB_NAMES))
else
DTB_LIST := $(dtb-y)
endif

targets += dtbs
subdir- := msm8974-g2-spr
endif

$(obj)/../%.dtb: $(src)/%.dts
	$(call if_changed_dep,dtc)

dtbs: $(addprefix $(obj)/../,$(DTB_LIST))

clean-files := *.dtb
