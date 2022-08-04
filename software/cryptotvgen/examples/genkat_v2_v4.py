#!/usr/bin/env python3

import os
import sys
from pathlib import Path

from cryptotvgen import cli

script_dir = Path(__file__).parent.resolve()

# to build the libs from the examples directory:
# $ cryptotvgen --prepare_lib --candidates_dir=../dummy_lwc_ref/


if __name__ == '__main__':
    blocks_per_segment = None
    ccw = 32
    #legal_widths = {8, 16, 32}
    #if len(sys.argv) > 1:
    #    ccw = int(sys.argv[1])  # make sure it's int
    #    assert ccw in legal_widths, f'ccw should be in {legal_widths}'
    #
    #    if len(sys.argv) > 2:
    #        blocks_per_segment = int(sys.argv[2])
    #else:
    #    sys.exit(f"Usage:\t{sys.argv[0]} <io-bits: {legal_widths}> [<max_block_per_sgmt>]")

    print(
        f'Generating test-vectors for io={ccw}' +
        (f" and max_block_per_sgmt={blocks_per_segment}" if blocks_per_segment else "") + "..."
    )

    dest_dir = f'testvectors/v2_v4{"_multi_segments" if blocks_per_segment else ""}_{ccw}'
    # ========================================================================
    # Create the list of arguments for cryptotvgen
    args = [
        '--lib_path', str(script_dir.parents[1] / 'ascon_ref' / 'lib'),  # Library path
        # Library name of AEAD algorithm (<algorithm_name>)
        '--aead', 'ascon128av12',
        # Library name of Hash algorithm (<algorithm_name>)
        '--hash', 'asconhashav12',
        '--io', str(ccw), str(ccw),                        # I/O width: PDI/DO and SDI width, respectively.
        '--key_size', '128',                               # Key size
        '--npub_size', '128',                              # Npub size
        '--nsec_size', '0',                                # Nsec size
        '--message_digest_size', '256',                    # Hash tag
        '--tag_size', '128',                               # Tag size
        '--block_size',    '128',                           # Data block size
        '--block_size_ad', '128',                           # AD block size
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
    #   Run routine (add at least one to args array)
    #
    #   Note: All the encrypt and decrypt operation specifiers refer to the
    #   input test vector  for hardware core. The actual process in the
    #   preparation of the test vector is based only on the encryption operation.
    # gen_test_routine = '--gen_test_routine 1 20 0'.split()
    # gen_random = '--gen_random 10'.split()

    # new key (bool), decrypt (bool), AD_LEN, PT_LEN, hash-mode (bool)
    # gen_custom = ['--gen_custom',
    #     '''\
    #     True,   False,      0,          20,         False:
    #     1,      0,          100,        500,        0
    #     ''']
    # gen_single = ['--gen_single',
    #     '1',                                # AEAD Encrypt(0)/AEAD Decrypt(1)/Hash(2)
    #     '000102030405060708090A0B0C0D0E0F', #Key
    #     '000102030405060708090A0B',         #Npub
    #     '000102030405060708090A0B0C0D0E0F', #Nsec (Ignored: nsec_size=0)
    #     '000102030405060708090A0B0C0D0E0F', #AD
    #     '000102030405060708090A0B0C0D0E0F', #DATA
    #     ]
    # gen_single_hash = ['--gen_single',
    #     '2',                                # AEAD Encrypt(0)/AEAD Decrypt(1)/Hash(2)
    #     '00000000000000000000000000000000', #Key
    #     '000000000000000000000000',         #Npub
    #     '00000000000000000000000000000000', #Nsec (Ignored: nsec_size=0)
    #     '00000000000000000000000000000000', #AD
    #     '000102030405060708090A0B0C0D0E0F', #DATA
    #     ]

    gen_test_routine = '--gen_test_routine 1 22 0'.split()
    # gen_hash = '--gen_hash 1 20 2'.split()
    # ========================================================================
    # Add option arguments together
    args += msg_format
    args += gen_test_routine
    # Add other test routines below
    # args += gen_hash
    # ========================================================================
    # Call program
    cli.run_cryptotvgen(args)

