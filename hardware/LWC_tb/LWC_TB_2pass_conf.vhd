configuration LWC_TB_2pass_conf of LWC_TB is
    for TB
        for uut : LWC
            use entity work.LWC_TB_2pass_uut; -- either RTL or Verilog netlist
        end for;
    end for;
end configuration;