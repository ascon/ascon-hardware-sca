GHDL=ghdl
GHDL_FLAGS=--std=08
GHDL_OPTIMIZE := -O3
GHDL_OPT := -frelaxed-rules --warn-no-vital-generic -frelaxed $(GHDL_OPTIMIZE)
GHDL_ELAB_OPTS := --mb-comments 
GHDL_WARNS := -Wbinding -Wreserved -Wlibrary -Wvital-generic -Wdelayed-checks -Wbody -Wspecs -Wunused --warn-no-runtime-error
MODULES_V1=\
	src_rtl/v1/LWC_config_32_2s.o\
	src_rtl/LWC/NIST_LWAPI_pkg.o\
	src_rtl/v1/design_pkg.o\
	src_rtl/LWC/FIFO.o\
	src_rtl/LWC/data_piso.o\
	src_rtl/LWC/data_sipo.o\
	src_rtl/LWC/key_piso.o\
	src_rtl/v1/Round.o\
	src_rtl/v1/CryptoCore_SCA.o\
	src_rtl/LWC/PostProcessor.o\
	src_rtl/LWC/PreProcessor.o\
	src_rtl/LWC/LWC_SCA.o\
	src_tb/v1/LWC_TB_SCA
MODULES_V2=\
	src_rtl/v2/LWC_config_32_2s.o\
	src_rtl/LWC/NIST_LWAPI_pkg.o\
	src_rtl/v2/design_pkg.o\
	src_rtl/LWC/FIFO.o\
	src_rtl/LWC/data_piso.o\
	src_rtl/LWC/data_sipo.o\
	src_rtl/LWC/key_piso.o\
	src_rtl/v2/Round.o\
	src_rtl/v2/CryptoCore_SCA.o\
	src_rtl/LWC/PostProcessor.o\
	src_rtl/LWC/PreProcessor.o\
	src_rtl/LWC/LWC_SCA.o\
	src_tb/v2/LWC_TB_SCA
MODULES_V3=\
	src_rtl/v3/LWC_config_32_3s.o\
	src_rtl/LWC/NIST_LWAPI_pkg.o\
	src_rtl/v3/design_pkg.o\
	src_rtl/LWC/FIFO.o\
	src_rtl/LWC/data_piso.o\
	src_rtl/LWC/data_sipo.o\
	src_rtl/LWC/key_piso.o\
	src_rtl/v3/Round.o\
	src_rtl/v3/CryptoCore_SCA.o\
	src_rtl/LWC/PostProcessor.o\
	src_rtl/LWC/PreProcessor.o\
	src_rtl/LWC/LWC_SCA.o\
	src_tb/v3/LWC_TB_SCA
MODULES_V4=\
	src_rtl/v4/LWC_config_32_3s.o\
	src_rtl/LWC/NIST_LWAPI_pkg.o\
	src_rtl/v4/design_pkg.o\
	src_rtl/LWC/FIFO.o\
	src_rtl/LWC/data_piso.o\
	src_rtl/LWC/data_sipo.o\
	src_rtl/LWC/key_piso.o\
	src_rtl/v4/Round.o\
	src_rtl/v4/CryptoCore_SCA.o\
	src_rtl/LWC/PostProcessor.o\
	src_rtl/LWC/PreProcessor.o\
	src_rtl/LWC/LWC_SCA.o\
	src_tb/v4/LWC_TB_SCA

v1: $(MODULES_V1)
	$(info More v1 testbench output can be found in log.txt or failed_testvectors.txt)

v2: $(MODULES_V2)
	$(info More v2 testbench output can be found in log.txt or failed_testvectors.txt)

v3: $(MODULES_V3)
	$(info More v3 testbench output can be found in log.txt or failed_testvectors.txt)

v4: $(MODULES_V4)
	$(info More v4 testbench output can be found in log.txt or failed_testvectors.txt)

# Binary depends on the object file
%: %.o
	$(GHDL) -e $(GHDL_FLAGS) $(GHDL_OPT) $(GHDL_WARNS) $(GHDL_ELAB_OPTS) LWC_TB
	$(GHDL) -r $(GHDL_FLAGS) $(GHDL_OPT) $(GHDL_WARNS) $(GHDL_ELAB_OPTS) LWC_TB

# Object file depends on source
%.o: %.vhd
	$(GHDL) -a $(GHDL_FLAGS) $(GHDL_OPT) $(GHDL_WARNS) $(GHDL_ELAB_OPTS) $<

.PHONY: clean
clean:
	$(info Cleaning up...)
	rm -f *.o *_TB_SCA work*.cf e*.lst failed_testvectors.txt result.txt log.txt lwc_tb

