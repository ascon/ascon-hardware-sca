#!/usr/bin/env python3

import os
import sys
from pathlib import Path

from cryptotvgen import cli

script_dir = Path(__file__).parent.resolve()

if __name__ == '__main__':
    blocks_per_segment = None
    ccw = 32
    dest_dir = f'testvectors/ascon128v12_{ccw}'
    # ========================================================================
    # Create the list of arguments for cryptotvgen
    args = [
        '--lib_path', str(script_dir.parents[1] / 'ascon_ref' / 'lib'),  # Library path
        # Library name of AEAD algorithm (<algorithm_name>)
        '--aead', 'ascon128v12',
        # Library name of Hash algorithm (<algorithm_name>)
        '--hash', 'asconhashv12',
        '--io', str(ccw), str(ccw),                        # I/O width: PDI/DO and SDI width, respectively.
        '--key_size', '128',                               # Key size
        '--npub_size', '128',                              # Npub size
        '--nsec_size', '0',                                # Nsec size
        '--message_digest_size', '256',                    # Hash tag
        '--tag_size', '128',                               # Tag size
        '--block_size',    '64',                           # Data block size
        '--block_size_ad', '64',                           # AD block size
        # '--ciph_exp',                                    # Ciphertext expansion
        # '--add_partial',                                 # ciph_exp option: add partial bit
        # '--ciph_exp_noext',                              # ciph_exp option: no block extension when a message is a multiple of a block size
        # '--offline',                                     # Offline cipher (Adds Length segment as the first input segment)
        '--dest', dest_dir,                                # destination folder
        '--max_ad', '80',                                  # Maximum random AD size
        '--max_d', '80',                                   # Maximum random message size
        '--max_io_per_line', '8',                          # Max number of w-bit I/O word per line
        '--human_readable',                                # Generate a human readable text file
        '--verify_lib',                                    # Verify reference enc/dec in reference code
                                                           # Note: (This option performs decryption for
                                                           #        each encryption operation used to
                                                           #        create the test vector)
    ]
    if blocks_per_segment:
        args += ['--max_block_per_sgmt', str(blocks_per_segment)]
    # ========================================================================
    # Alternative way of creating an option argument
    #   message format
    msg_format = '--msg_format npub ad data tag'.split()
    gen_test_routine = '--gen_test_routine 1 22 0'.split()
    args += msg_format
    args += gen_test_routine
    # ========================================================================
    # Call program
    cli.run_cryptotvgen(args)

