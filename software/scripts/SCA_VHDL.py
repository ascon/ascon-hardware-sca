#!/usr/bin/env python3
# requires  Python 3.6+

## example:  
# ./scripts/SCA_VHDL.py LWC_tb/LWC_TB.vhd LWC_tb/LWC_TB_SCA.vhd
# ./scripts/SCA_VHDL.py LWC_tb/LWC.vhd LWC_tb/LWC_SCA.vhd

import argparse
from pathlib import Path
from functools import reduce
import re

parser = argparse.ArgumentParser(
    description='Generate _SCA version of RTL and TB VHDL files')
parser.add_argument('in_file', type=argparse.FileType('r'), help='input file')
parser.add_argument('out_file', type=argparse.FileType('w'), help='input file')


args = parser.parse_args()

ROI_START = "--*** SCA ***--"
ROI_END = "--***********--"
PROCESS_NEXT = "--/" # + or -

in_roi = False
uncomment_counter = 0



for line in args.in_file.readlines():
    line_trimmed = line.strip()
    if line_trimmed == ROI_START:
        in_roi = True
    elif line_trimmed == ROI_END:
        in_roi = False
    elif in_roi and line_trimmed.startswith(PROCESS_NEXT):
        plus_minus = line_trimmed[len(PROCESS_NEXT):]
        l = len(plus_minus)
        if l > 0:
            if all(map(lambda v: v=='+', plus_minus)):
                uncomment_counter = l
            elif all(map(lambda v: v=='-', plus_minus)):
                uncomment_counter = -l
    elif in_roi and uncomment_counter > 0:
        uncomment_counter = uncomment_counter - 1;
        line = re.sub(r'^(\s*)--\s([\S].*)', r'\1\2', line)
        args.out_file.write(line)
    elif in_roi and uncomment_counter < 0:
        line = re.sub(r'^(\s*)(\S.*)', r'\1-- \2', line)
        uncomment_counter = uncomment_counter + 1;
    else:
        args.out_file.write(line)