GHDL=ghdl
GHDLFLAGS=

MODULES=\
	src_rtl/LWC/data_piso.o\
	src_rtl/LWC/data_sipo.o\
	src_rtl/LWC/FIFO.o\
	src_rtl/LWC/key_piso.o\
	src_rtl/LWC/LWC_SCA.o\
	src_rtl/LWC/NIST_LWAPI_pkg.o\
	src_rtl/LWC/PostProcessor.o\
	src_rtl/LWC/PreProcessor.o\
	src_rtl/LWC/v1/CryptoCore_SCA.o\
	src_rtl/LWC/v1/design_pkg.o\
	src_rtl/LWC/v1/LWC_config_32_2s.o\
	src_rtl/LWC/v1/Round.o\
	src_tb/LWC_TB_SCA

test: $(MODULES)
	./LWC_TB_SCA --vcd=LWC_TB_SCA.vcd

# Binary depends on the object file
%: %.o
	$(GHDL) -e $(GHDLFLAGS) $@

# Object file depends on source
%.o: %.vhd
	$(GHDL) -a $(GHDLFLAGS) $<

clean:
	echo "Cleaning up..."
	rm -f *.o *_TB_SCA work*.cf e*.lst
