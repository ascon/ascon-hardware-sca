proc reportCriticalPaths { fileName } {
    # Open the specified output file in write mode
    set FH [open $fileName w]
    # Write the current date and CSV format to a file header
    puts $FH "#\n# File created on [clock format [clock seconds]]\n#\n"
    puts $FH "Startpoint,Endpoint,DelayType,Slack,#Levels,#LUTs"
    # Iterate through both Min and Max delay types
    foreach delayType {max min} {
        # Collect details from the 50 worst timing paths for the current analysis
        # (max = setup/recovery, min = hold/removal)
        # The $path variable contains a Timing Path object.
        foreach path [get_timing_paths -delay_type $delayType -max_paths 50 -nworst 1] {
            # Get the LUT cells of the timing paths
            # set luts [get_cells -filter {REF_NAME =~ LUT*} -of_object $path] # print  ,[llength $luts] << TODO warnings
            # Get the startpoint of the Timing Path object
            set startpoint [get_property STARTPOINT_PIN $path]
            # Get the endpoint of the Timing Path object
            set endpoint [get_property ENDPOINT_PIN $path]
            # Get the slack on the Timing Path object
            set slack [get_property SLACK $path]
            # Get the number of logic levels between startpoint and endpoint
            set levels [get_property LOGIC_LEVELS $path]
            # Save the collected path details to the CSV file
            puts $FH "$startpoint,$endpoint,$delayType,$slack,$levels"
        }
    }
    # Close the output file
    close $FH
    puts "CSV file $fileName has been created.\n"
    return 0
}; # End PROC

proc errorExit {errorString} {
    puts "Error: $errorString"
    exit 1
}
########################################################################
########################################################################

set child_scripts_dir [file dirname [info script]]
source ${child_scripts_dir}/interface.tcl



file mkdir ${results_dir}
file mkdir ${reports_dir}
file mkdir [file join ${reports_dir} post_synth]
file mkdir [file join ${reports_dir} post_place]
file mkdir [file join ${reports_dir} post_route]
file mkdir ${checkpoints_dir}

# suppress soem messages
# warning partial connection
set_msg_config -id "\[Synth 8-350\]" -suppress
# info do synthesis
set_msg_config -id "\[Synth 8-256\]" -suppress
set_msg_config -id "\[Synth 8-638\]" -suppress
# BRAM mapped to LUT due to optimization
set_msg_config -id "\[Synth 8-3969\]" -suppress
# BRAM with no output register
set_msg_config -id "\[Synth 8-4480\]" -suppress
# DSP without input pipelining
set_msg_config -id "\[Drc 23-20\]" -suppress
# Update IP version
set_msg_config -id "\[Netlist 29-345\]" -suppress   


set parts [get_parts]

puts "\n<Step 0>"

if {[lsearch -exact $parts ${part}] < 0} {
    puts "ERROR: device ${part} is not supported!"
    puts "Supported devices: $parts"
    quit
}

puts "Targeting device: ${part}"

foreach path ${verilog_files} {
  puts "Reading Verilog/SystemVerilog file ${path}"
  if { [catch {eval read_verilog -sv ${path} } myError]} {
      errorExit $myError
  }
}

foreach path ${vhdl_files} {
  set vhdl_std_opt [expr {$vhdl_std == "08" ?  "-vhdl2008": ""}];
  puts "Reading VHDL file ${path} ${vhdl_std_opt}"
  if { [catch {eval read_vhdl ${vhdl_std_opt} ${path} } myError]} {
      errorExit $myError
  }
}

set xdc_file [open clock.xdc w]
puts $xdc_file "create_clock -period ${clock_period} -name clock \[get_ports clk\]"
close $xdc_file
read_xdc clock.xdc

puts "\n<Step 1>"

eval synth_design -part ${part} -top ${top_module_name} ${synth_options}
#write_verilog -force ${results_dir}/${top_module_name}_synth_rtl.v

# report_utilization -file ${reports_dir}/pre_opt_utilization.rpt
puts "\n<Step 2>"
eval opt_design ${opt_options}


puts "==== Synthesis and Mapping Steps Complemeted ====\n"
write_checkpoint -force ${checkpoints_dir}/post_synth
report_timing_summary -file ${reports_dir}/post_synth/timing_summary.rpt
report_utilization -file ${reports_dir}/post_synth/utilization.rpt
reportCriticalPaths ${reports_dir}/post_synth/critpath_report.csv
report_methodology  -file ${reports_dir}/post_synth/methodology.rpt
# report_power -file ${reports_dir}/post_synth/power.rpt

puts "\n<Step 3>"
eval place_design ${place_options}

puts "\n<Step 4>"
eval phys_opt_design ${phys_opt_options}

puts "\n<Step 5>"
eval power_opt_design

write_checkpoint -force ${checkpoints_dir}/post_place
report_timing_summary -max_paths 10                             -file ${reports_dir}/post_place/timing_summary.rpt}

puts "==== Placement Steps Complemeted ====\n"

puts "\n<Step 6>"
eval route_design ${route_options}

puts "\n<Step 7>"
eval phys_opt_design ${phys_opt_options}

write_checkpoint -force ${checkpoints_dir}/post_route
report_timing_summary -max_paths 10                             -file ${reports_dir}/post_route/timing_summary.rpt
report_timing  -sort_by group -max_paths 100 -path_type summary -file ${reports_dir}/post_route/timing.rpt
reportCriticalPaths ${reports_dir}/post_route/critpath_report.csv
report_clock_utilization                                        -file ${reports_dir}/post_route/clock_utilization.rpt
report_utilization                                              -file ${reports_dir}/post_route/utilization.rpt
report_utilization -hierarchical                                -file ${reports_dir}/post_route/hierarchical_utilization.rpt
report_power                                                    -file ${reports_dir}/post_route/power.rpt
report_drc                                                      -file ${reports_dir}/post_route/drc.rpt
report_ram_utilization                                          -file ${reports_dir}/post_route/ram_utilization.rpt -append -detail
report_methodology                                              -file ${reports_dir}/post_route/methodology.rpt

puts "==== Routing Steps Complemeted ====\n"

puts "Writing implemented netlist Verilog and SDF..."
write_verilog -include_xilinx_libs -force ${results_dir}/${top_module_name}_impl_netlist.v
write_sdf -force ${results_dir}/${top_module_name}_impl_netlist.v.sdf


# write_vhdl -force ${results_dir}/${top_module_name}_impl_netlist.vhdl
write_xdc -no_fixed_only -force ${results_dir}/${top_module_name}_impl.xdc

# write_bitstream -force ${results_dir}/${top_module_name}.bit


puts "\n\n**** Vivado run completed ****\n"
puts "** Number of Errors:             [get_msg_config -severity {ERROR} -count]"
puts "** Number of Critical Warnings:  [get_msg_config -severity {CRITICAL WARNING} -count]"
puts "** Number of Warnings:           [get_msg_config -severity {WARNING} -count]\n\n"


set timing_slack [get_property SLACK [get_timing_paths]]
puts "Final timing slack: $timing_slack ns"

if {$timing_slack < 0} {
    puts "ERROR: Failed to meet timing by $timing_slack, see [file join ${reports_dir} post_route timing_summary.rpt]"
    exit 1
}

quit
