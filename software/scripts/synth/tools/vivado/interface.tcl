set output_dir          [string trim $::env(VIVADO_OUTPUT_DIR)]
set part                [string trim $::env(FPGA_PART)]
set top_module_name     [string trim $::env(TOP)]
set synth_options       [split [string trim $::env(SYNTH_OPTIONS)]]
set opt_options         [split [string trim $::env(OPT_OPTIONS)]]
set place_options       [split [string trim $::env(PLACE_OPTIONS)]]
set route_options       [split [string trim $::env(ROUTE_OPTIONS)]]
set phys_opt_options    [split [string trim $::env(PYS_OPT_OPTIONS)]]

set verilog_files       $::env(VERILOG_FILES)
set vhdl_files          $::env(VHDL_FILES)
set clock_period        [string trim $::env(CLOCK_PERIOD)]
set vhdl_std            [string trim $::env(VHDL_STD)]


set reports_dir         ${output_dir}/reports
set results_dir         ${output_dir}/reports
set checkpoints_dir     ${output_dir}/checkpoints