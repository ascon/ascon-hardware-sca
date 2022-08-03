GHDL=ghdl
GHDLFLAGS=--std=08

MODULES=\
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

test: $(MODULES)
	./LWC_TB --vcd=v1.vcd

# Binary depends on the object file
%: %.o
	$(GHDL) -r $(GHDLFLAGS) LWC_TB

# Object file depends on source
%.o: %.vhd
	$(GHDL) -a $(GHDLFLAGS) $<

clean:
	echo "Cleaning up..."
	rm -f *.o *_TB_SCA work*.cf e*.lst
