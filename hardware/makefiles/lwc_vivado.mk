
SYNTH_FRAMEWORK_ROOT=$(realpath $(LWC_ROOT)/hardware/scripts/synth)

VIVADO_RUN_TCL=$(SYNTH_FRAMEWORK_ROOT)/tools/vivado/run.tcl

VIVADO_GENERICS_OPTIONS=$(shell $(PYTHON3_BIN) $(LWC_ROOT)/hardware/scripts/config_parser.py vivado_generics $(CONFIG_LOC))

################################################################################
# User configurable variables
################################################################################
FPGA_PART ?= xc7a100tcsg324-1
# SYNTH_OPTIONS ?= -assert -flatten_hierarchy rebuilt -retiming -directive AreaOptimized_medium $(VIVADO_GENERICS_OPTIONS)
SYNTH_OPTIONS ?= -assert -flatten_hierarchy rebuilt -retiming -directive Default $(VIVADO_GENERICS_OPTIONS)
OPT_OPTIONS ?= -directive ExploreWithRemap # extra optimization pass
PLACE_OPTIONS ?= -directive Default
ROUTE_OPTIONS ?= -directive Default
PYS_OPT_OPTIONS ?= -directive Default
VIVADO_BIN ?= vivado
################################################################################

# $(eval VARS := $(shell $(PYTHON3_BIN) $(SCRIPTS_DIR)/config_parser.py vars $(CONFIG_LOC)))
# $(foreach v,$(VARS),$(eval $(v)))

.PHONY: synth-vivado clean-vivado help-vivado

VIVADO_DEBUG ?=

VIVADO_CMD=$(VIVADO_BIN) -mode batch -nojournal $(if $(VIVADO_DEBUG),,-notrace) -source $(VIVADO_RUN_TCL)

VIVADO_OUTPUT_DIR=vivado

#TODO FIX this mess!
export FPGA_PART
export VIVADO_OUTPUT_DIR
export SYNTH_OPTIONS
export OPT_OPTIONS
export PLACE_OPTIONS
export ROUTE_OPTIONS
export PYS_OPT_OPTIONS
export CLOCK_PERIOD

$(TOOL_RUN_DIR)/docker.env : $(TOOL_RUN_DIR) $(VERILOG_FILES) $(VHDL_FILES) $(FORCE_REBUILD) config-vars
	$(file > $@)
	$(foreach v,$(.VARIABLES),$(if $(filter-out .%,$(filter file,$(origin $(v)))), $(file >>$@,$(strip $(v)=$($(v))))))
	@touch $@

synth-vivado: $(TOOL_RUN_DIR)/docker.env $(VERILOG_FILES) $(VHDL_FILES) $(TOOL_RUN_DIR)/docker.env config-vars
	cd $(TOOL_RUN_DIR) && $(VIVADO_CMD)

help-vivado:
	@printf "%b" "$(CYAN)synth-vivado variables$(NO_COLOR):\n";
	@printf "%b" "FPGA_PART \t Target FPGA part identifier \n";
	@printf "%b" "CLOCK_PERIOD \t Target clock period in 'ns' \n";
	@printf "%b" "SYNTH_OPTIONS \t Synthesis options \n";
	@printf "%b" "OPT_OPTIONS \t Optimization options \n";
	@printf "%b" "PYS_OPT_OPTIONS  Physical optimization options \n";
	@printf "%b" "PLACE_OPTIONS \t Placing options \n";
	@printf "%b" "ROUTE_OPTIONS \t Routing options \n";
	@echo

clean-vivado:
	@rm -rf $(TOOL_RUN_DIR)/$(VIVADO_OUTPUT_DIR)/reports $(TOOL_RUN_DIR)/$(VIVADO_OUTPUT_DIR)/results $(TOOL_RUN_DIR)/$(VIVADO_OUTPUT_DIR)/checkpoints_dir 
