#!/usr/bin/env python3
# -*- coding: utf-8 -*

import copy
import os
import sys
from pathlib import Path

from cryptotvgen import cli

script_dir = Path(__file__).parent.resolve()

# to build the libs from the examples directory:
# $ cryptotvgen --prepare_lib --candidates_dir=../../

# Algorithm information required
dest_folder = "testvectors/dummy_lwc_32"
aead_lib_name = 'dummy_lwc'  # Library name of AEAD algorithm
# Comment out if not supported
hash_lib_name = 'dummy_lwc'  # Library name of hash algorithm
PDI_width = 32 # I/O width: PDI/DO bits
SDI_width = 32 # I/O width: SDI bits
key_size = 128 # bits
npub_size = 96 # bits
nsec_size = 0  # bits
tag_size = 128 # bits
block_size_message  = 128 # bits
block_size_ad = 128 # bits
block_size_msg_digest = 256 # bits

# Typically message come in the order. Update if necessary(unlikely)
msg_format = '--msg_format npub ad data tag'.split()

def gen_custom_string_aead(new_key, enc_dec):
        # only ad
        gen_string = ""
        gen_string += f"{new_key},{enc_dec},{5*block_size_ad//8},                        0,0:"
        gen_string += f"{new_key},{enc_dec},{4*block_size_ad//8},                        0,0:"
        gen_string += f"{new_key},{enc_dec},                1536,                        0,0:"
        gen_string += f"{new_key},{enc_dec},                  64,                        0,0:"
        gen_string += f"{new_key},{enc_dec},                  16,                        0,0:"
        gen_string += f"{new_key},{enc_dec},                   0,{5*block_size_message//8},0:"
        gen_string += f"{new_key},{enc_dec},                   0,{4*block_size_message//8},0:"
        gen_string += f"{new_key},{enc_dec},                   0,                     1536,0:"
        gen_string += f"{new_key},{enc_dec},                   0,                       64,0:"
        gen_string += f"{new_key},{enc_dec},                   0,                       16,0:"
        gen_string += f"{new_key},{enc_dec},{5*block_size_ad//8},{5*block_size_message//8},0:"
        gen_string += f"{new_key},{enc_dec},{4*block_size_ad//8},{4*block_size_message//8},0:"
        gen_string += f"{new_key},{enc_dec},                1536,                     1536,0:"
        gen_string += f"{new_key},{enc_dec},                  64,                       64,0:"
        gen_string += f"{new_key},{enc_dec},                  16,                       16,0:"
        return gen_string

def gen_custom_string_hash():
        hash_string = ""
        hash_string += f"0,0,0,{5*block_size_msg_digest//8},1:"
        hash_string += f"0,0,0,{4*block_size_msg_digest//8},1:"
        hash_string += f"0,0,0,1536,1:"
        hash_string += f"0,0,0,64,1:"
        hash_string += f"0,0,0,16,1:"
        return hash_string

def finish_custom():
    # Final message must not contain ":" at the end
    return "1,0,0,0,0"

def blanket_message_test():
    return_string = ""
    for ad_size in range(2*block_size_ad//8):
        for mess_size in range(2*block_size_message//8):
            return_string+=f"1,0,{ad_size},{mess_size},0:"
    return return_string

def blanket_message_hash_test():
    return_string = ""
    for hash_size in range(4*block_size_msg_digest//8):
            return_string+=f"0,0,0,{hash_size},1:"
    return return_string

if __name__ == '__main__':
    # Print the help text
    if (len(sys.argv) > 1 and sys.argv[1] == '-h'):
        sys.exit(cli.run_cryptotvgen(sys.argv[1:]))
    # Create the list of arguments for cryptotvgen
    args = [
        '--lib_path', str(script_dir.parents[1] / 'dummy_lwc_ref' / 'lib'),
        '--aead', aead_lib_name,
        '--io', f'{PDI_width}', f'{SDI_width}',
        '--key_size', f'{key_size}',
        '--block_size', f'{block_size_message}',
        '--block_size_ad', f'{block_size_ad}',
        '--npub_size', f'{npub_size}',
        '--nsec_size', f'{nsec_size}',
        '--tag_size', f'{tag_size}',
        '--max_io_per_line', '8',
        '--human_readable', '--verify_lib',
        ]
    if hash_lib_name is not None:
        args += ['--hash', hash_lib_name,
                 '--message_digest_size', f'{block_size_msg_digest}', 
                ]
        args += ['--hash', hash_lib_name,]
    orig_args = args.copy()

    # Desired measurements with new key every time
    args += msg_format + ['--dest', os.path.join(dest_folder,"throughput_new_key")]
    gen_cus_string = gen_custom_string_aead(1,0) + gen_custom_string_aead(1,1)
    if hash_lib_name is not None:
        gen_cus_string += gen_custom_string_hash() + finish_custom()
    else:
        gen_cus_string += finish_custom()
    args += ['--gen_custom', gen_cus_string]
    cli.run_cryptotvgen(args)

    # Desired measurements using the same key every time
    args = orig_args.copy()
    args += msg_format + ['--dest', os.path.join(dest_folder,"throughput_reuse_key")]
    # First message is just providing the new key
    gen_cus_string = "1,0,0,0,0:" + gen_custom_string_aead(0,0) + gen_custom_string_aead(0,1)
    gen_cus_string += finish_custom()
    args += ['--gen_custom', gen_cus_string]
    cli.run_cryptotvgen(args)

    # Blanket test all possible message AD/PT message combinations between 0 and 2 x blocksize
    args = orig_args.copy()
    args += msg_format + ['--dest', os.path.join(dest_folder,"blanket_support_test")]
    gen_cus_string = blanket_message_test() + finish_custom()
    args += ['--gen_custom', gen_cus_string]
    cli.run_cryptotvgen(args)

    if hash_lib_name is not None:
        args = orig_args.copy()
        args += msg_format + ['--dest', os.path.join(dest_folder,"blanket_hash_support_test")]
        gen_cus_string = blanket_message_hash_test() + finish_custom()
        args += ['--gen_custom', gen_cus_string]
        cli.run_cryptotvgen(args)
     



