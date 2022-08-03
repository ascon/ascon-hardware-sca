WORK_DIR=work

VCS_SIMV=simv

$(WORK_DIR) :
	-@mkdir -p $@

synopsys_sim.setup :
	echo "WORK  > default" > $@
	echo "default : $(WORK_DIR)" >> $@
	
ifeq ($(strip $(VERILOG_FILES)),)
VCS_VLOGAN_CMD :=
else
VCS_VLOGAN_CMD := vlogan -full64 -nc -sverilog +v2k -work $(WORK_DIR) +warn=all $(VERILOG_FILES) -timescale=1ns/1ps +incdir+../../../vclib/src
endif

VCS_GENERICS_OPTS=$(shell $(PYTHON3_BIN) $(LWC_ROOT)/hardware/scripts/config_parser.py vcs_generics $(CONFIG_LOC))

.PHONY: sim-vcs clean-vcs


VCS_VHDLAN_ARGS = -full64 -nc -w WORK $(SIM_VHDL_FILES) -timescale=1ns/1ps -cycle -event 

ifeq ($(strip $(VHDL_STD)),08)
VCS_VHDLAN_ARGS += -vhdl08
endif

$(SIM_TOP) : $(FORCE_REBUILD) Makefile $(WORK_DIR) $(SIM_VHDL_FILES) $(VERILOG_FILES) synopsys_sim.setup Makefile
	$(VCS_VLOGAN_CMD)
	vhdlan $(VCS_VHDLAN_ARGS)
	vcs $(SIM_TOP) -full64 -nc -j$(NTHREADS) -notice +lint=all,noVCDE,noTFIPC,noIWU,noOUDPE -l vcs.log

sim-vcs : clean-vcs $(SIM_TOP)
	./$(VCS_SIMV) -nc -lca +define+CLOCK_PERIOD=$(CLOCK_PERIOD) $(VCS_GENERICS_OPTS) -l $@

clean-vcs :
	-@rm -rf $(WORK_DIR) csrc ucli.key simv.daidir $(VCS_SIMV) synopsys_sim.setup
