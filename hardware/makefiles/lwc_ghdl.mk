.DELETE_ON_ERROR:

GHDL_BIN ?= ghdl

GHDL_OPTIMIZE ?= -O3

GHDL_WARNS ?= -Wbinding -Wreserved -Wlibrary -Wvital-generic -Wdelayed-checks -Wbody -Wspecs -Wunused --warn-no-runtime-error

ifneq ($(strip $(VCD_FILE)),)
GHDL_SIM_OPTS += --vcd=$(VCD_FILE)
endif
ifneq ($(strip $(VCDGZ_FILE)),)
GHDL_SIM_OPTS += --vcdgz=$(VCDGZ_FILE)
endif
ifneq ($(strip $(GHW_FILE)),)
GHDL_SIM_OPTS += --wave=$(GHW_FILE)
endif

GHDL_IEEE_SYNOPSYS ?=


SIM_ONLY_VHDL_FILES := $(VHDL_ADDITIONS) $(LWC_TB) 
SIM_VHDL_FILES = $(VHDL_FILES) $(SIM_ONLY_VHDL_FILES)

GHDL_GENERICS_OPTS=$(shell $(PYTHON3_BIN) $(LWC_ROOT)/hardware/scripts/config_parser.py ghdl_generics $(CONFIG_LOC))

GHDL_STD_OPT = --std=$(if $(filter $(VHDL_STD),93),93c,$(VHDL_STD))

GHDL_ANALYSIS_OPTS = -frelaxed-rules --warn-no-vital-generic -frelaxed $(GHDL_OPTIMIZE) --mb-comments \
	$(if $(GHDL_IEEE_SYNOPSYS),--ieee=synopsys -fsynopsys,) $(GHDL_STD_OPT)

GHDL_ELAB_OPTS = $(GHDL_STD_OPT) $(if $(GHDL_IEEE_SYNOPSYS),-fsynopsys,)

### GHDL analyze testbench files, elaborate, and run
.PHONY: sim-ghdl help-ghdl clean-ghdl lint-vhdl-synth $(WORK_LIB)-obj$(VHDL_STD).cf

### GHDL analyse
$(WORK_LIB)-obj$(VHDL_STD).cf: $(SIM_VHDL_FILES) $(FORCE_REBUILD) config-vars
ifneq ($(strip $(VHDL_FILES)),)
	@rm -f $@ 
	$(GHDL_BIN) -a $(GHDL_ANALYSIS_OPTS) $(GHDL_WARNS) $(SIM_VHDL_FILES)
endif

sim-ghdl: $(WORK_LIB)-obj$(VHDL_STD).cf config-vars
	$(GHDL_BIN) -e $(GHDL_ELAB_OPTS) $(SIM_TOP) 
	$(GHDL_BIN) -r $(GHDL_STD_OPT) $(SIM_TOP) $(GHDL_SIM_OPTS) $(GHDL_GENERICS_OPTS)

ifeq ($(strip $(VHDL_FILES)),)
YOSYS_READ_VHDL_CMD = 
else
YOSYS_READ_VHDL_CMD = ghdl $(GHDL_ANALYSIS_OPTS) $(GHDL_WARNS) $(TOP);
endif

GHDL_SYNTH_REDIRECT ?= /dev/null


VHDL_LINT_CMD = $(GHDL_BIN) -s $(GHDL_ANALYSIS_OPTS) --mb-comments $(GHDL_OPT) $(GHDL_WARNS)
lint-ghdl: $(VHDL_FILES) config-vars
ifneq ($(strip $(VHDL_FILES)),)
	$(VHDL_LINT_CMD) $(VHDL_FILES)
endif

lint-ghdl-synth: $(WORK_LIB)-obj$(VHDL_STD).cf
ifneq ($(strip $(VHDL_FILES)),)
	$(GHDL_BIN) --synth $(GHDL_STD_OPT) $(GHDL_ANALYSIS_OPTS) $(GHDL_WARNS) $(TOP) > $(GHDL_SYNTH_REDIRECT)
endif

help-ghdl:
	@printf "%b" "$(CYAN)GHDL variables$(NO_COLOR):\n";
	@printf "%b" "$(CYAN)sim-ghdl variables$(NO_COLOR):\n";
	@printf "%b" "VCD_FILE \t filename to generate VCD wave\n";
	@printf "%b" "VCDGZ_FILE \t filename to generate VCD wave, gziped\n";
	@printf "%b" "GHW_FILE \t filename to GHW wave (better support for VHDL types)\n";
	@printf "%b" "GHDL_OPTIMIZE \t Set GHDL optimization, default: -O3\n";
	@echo

GHDL_DOT_O_FILES = $(patsubst %.vhd,%.o,$(patsubst %.vhdl,%.o,$(notdir $(SIM_VHDL_FILES))))

clean-ghdl:
	-@rm -f *-obj*.cf $(SIM_TOP) e~*.o $(GHDL_DOT_O_FILES)
