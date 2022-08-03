YOSYS_FPGA ?= xc7

YOSYS_GHDL_MODULE := -m ghdl

ifeq ($(strip $(VERILOG_FILES)),)
YOSYS_READ_VERILOG_CMD := 
else
YOSYS_READ_VERILOG_CMD := read_verilog $(VERILOG_FILES);
endif

ifeq ($(strip $(YOSYS_FPGA)),xc7)
# $(info Yosys FPGA target: Xilinx 7 Series)
YOSYS_SYNTH_CMD := synth_xilinx -widemux 6 -flatten -retime -nobram -arch xc7
else ifeq ($(strip $(YOSYS_FPGA)),ice40)
# $(info Yosys FPGA target: Lattice iCE40)
YOSYS_SYNTH_CMD := synth_ice40 -retime -nobram
else ifeq ($(strip $(YOSYS_FPGA)),ecp5)
# $(info Yosys FPGA target: Lattice ECP5)
YOSYS_SYNTH_CMD := synth_ecp5 -retime -nobram
else
$(error unsupported YOSYS_FPGA=$(YOSYS_FPGA) )
endif


.PHONY: synth-yosys-fpga help-yosys clean-vcs

synth-yosys-fpga-$(YOSYS_FPGA).json: $(WORK_LIB)-obj$(VHDL_STD).cf $(VERILOG_FILES) config-vars
	$(YOSYS_BIN) $(YOSYS_GHDL_MODULE) -p "$(YOSYS_READ_VERILOG_CMD) $(YOSYS_READ_VHDL_CMD) $(YOSYS_SYNTH_CMD) -top $(TOP); write_json $@ ; check -assert; stat"

synth-yosys-fpga: synth-yosys-fpga-$(YOSYS_FPGA).json

help-yosys:
	@printf "%b" "$(CYAN)synth-yosys-fpga$(NO_COLOR):\n";
	@printf "%b" "YOSYS_FPGA \t Set target FPGA family: xc7, ic40, or ecp5\n";
	@echo

clean-yosys-fpga :
	-@rm -rf synth-yosys-fpga-*.json

