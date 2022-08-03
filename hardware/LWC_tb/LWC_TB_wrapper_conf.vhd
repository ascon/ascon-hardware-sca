configuration LWC_TB_wrapper_conf of LWC_TB is
    for TB
        for all : LWC
            use entity work.LWC_wrapper; -- either RTL or Verilog netlist
        end for;
    end for;
end configuration;