ifndef LWC_ROOT
$(error LWC_ROOT must be defined in design-specific Makefile)
endif

MIN_MAKE_VERSION := 4.1

ifeq ($(MAKE_VERSION),)
$(error MAKE_VERSION was not supported. Use GNU make >= $(MIN_MAKE_VERSION))
endif

MAKE_VERSION_OK ?= $(filter $(MIN_MAKE_VERSION),$(firstword $(sort $(MAKE_VERSION) $(MIN_MAKE_VERSION))))

ifeq ($(MAKE_VERSION_OK),)
# $(warning Detected `make` version ($(MAKE_VERSION)) is not fully supported! Please use GNU make >= $(MIN_MAKE_VERSION))
endif

LWC_ROOT := $(realpath $(LWC_ROOT))
HW_DIR := $(LWC_ROOT)/hardware

include $(HW_DIR)/makefiles/lwc_common.mk
include $(HW_DIR)/makefiles/lwc_ghdl.mk
include $(HW_DIR)/makefiles/lwc_lint.mk
include $(HW_DIR)/makefiles/lwc_yosys_fpga.mk
include $(HW_DIR)/makefiles/lwc_vcs.mk
include $(HW_DIR)/makefiles/lwc_vivado.mk
