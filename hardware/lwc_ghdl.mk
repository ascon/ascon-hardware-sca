ifeq ($(strip $(LWC_GHDL_INCLUDED)),)
LWC_GHDL_INCLUDED=1

GHDL := ghdl

GHDL_OPTIMIZE := -O3

GHDL_OPT := -frelaxed-rules --warn-no-vital-generic -frelaxed $(GHDL_OPTIMIZE)
GHDL_ELAB_OPTS := --mb-comments 
GHDL_WARNS := -Wbinding -Wreserved -Wlibrary -Wvital-generic -Wdelayed-checks -Wbody -Wspecs -Wunused --warn-no-runtime-error
GHDL_SIM_OPTS :=

ifeq ($(strip $(VHDL_STD)),93)
GHDL_OPT += --std=93c
else
GHDL_OPT += --std=$(VHDL_STD)
endif

ifneq ($(strip $(VCD_FILE)),)
GHDL_SIM_OPTS += --vcd=$(VCD_FILE)
endif
ifneq ($(strip $(VCDGZ_FILE)),)
GHDL_SIM_OPTS += --vcdgz=$(VCDGZ_FILE)
endif
ifneq ($(strip $(GHW_FILE)),)
GHDL_SIM_OPTS += --wave=$(GHW_FILE)
endif


### GHDL analyse
$(WORK_LIB)-obj$(VHDL_STD).cf: $(VHDL_FILES) Makefile
ifneq ($(strip $(VHDL_FILES)),)
	$(GHDL) -a $(GHDL_OPT) $(GHDL_WARNS) $(VHDL_FILES)
endif

SIM_ONLY_VHDL_FILES := $(VHDL_ADDITIONS) $(LWC_TB) 
SIM_VHDL_FILES = $(VHDL_FILES) $(SIM_ONLY_VHDL_FILES)

GENERICS_OPTS = $(shell python3 $(LWC_ROOT)/scripts/config_parser.py)

$(info GENERICS_OPTS=$(GENERICS_OPTS))

### GHDL analyze testbench files, elaborate, and run
sim-ghdl: $(WORK_LIB)-obj$(VHDL_STD).cf $(SIM_VHDL_FILES) Makefile
	$(GHDL) -a $(GHDL_OPT) $(GHDL_WARNS) $(GHDL_ELAB_OPTS) $(SIM_VHDL_FILES) $(LWC_TB)
	$(GHDL) -e $(GHDL_OPT) $(GHDL_WARNS) $(GHDL_ELAB_OPTS) $(SIM_TOP) 
	$(GHDL) -r $(SIM_TOP) $(GHDL_SIM_OPTS) $(GENERICS_OPTS) $(VCD_OPT)

ifeq ($(strip $(VHDL_FILES)),)
YOSYS_READ_VHDL_CMD := 
else
YOSYS_READ_VHDL_CMD := ghdl $(GHDL_OPT) $(GHDL_WARNS) $(TOP);
endif

clean-ghdl:
	-@rm -f $(WORK_LIB)-obj$(VHDL_STD).cf $(SIM_TOP) $(patsubst %.vhd,%.o,$(patsubst %.vhdl,%.o,$(notdir $(SIM_VHDL_FILES))))
endif