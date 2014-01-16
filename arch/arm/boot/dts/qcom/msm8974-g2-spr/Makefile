ifeq ($(CONFIG_OF),y)
dtb-$(CONFIG_ARCH_MSM8974) += msm8974-v2-2-g2-spr.dtb \
	msm8974-v2-g2-spr.dtb \
	msm8974-g2-spr.dtb

DTB_NAMES := $(subst $\",,$(CONFIG_BUILD_ARM_APPENDED_DTB_IMAGE_NAMES))
ifneq ($(DTB_NAMES),)
DTB_LIST := $(addsuffix .dtb,$(DTB_NAMES))
else
DTB_LIST := $(dtb-y)
endif

targets += dtbs
endif

$(obj)/../%.dtb: $(src)/%.dts
	$(call if_changed_dep,dtc)

dtbs: $(addprefix $(obj)/../,$(DTB_LIST))

clean-files := *.dtb
