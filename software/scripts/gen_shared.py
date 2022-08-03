#!/usr/bin/env python3
# requires  Python 3.6+

import secrets
import argparse
import logging
from pathlib import Path
from functools import reduce
import sys

parser = argparse.ArgumentParser(
    description='Generates shared testvectors and RDI')

log = logging.getLogger(__name__)


def xor(l, r):
    return bytes(a ^ b for a, b in zip(l, r))


INS_PREAMBLE = "INS = "
HDR_PREAMBLE = "HDR = "
DAT_PREAMBLE = "DAT = "


def gen_shares(in_file, num_shares, w_nbytes=0):
    in_path = Path(in_file.name)
    out_file = in_path.parent / (in_path.stem + f"_shared_{num_shares}.txt")
    num_tests = 0
    with open(out_file, 'w') as o:
        o.write(
            f"#\n# Shared version of {in_path.name} split into {num_shares} shares\n#\n")
        for line in in_file.readlines():
            if len(line) > len(INS_PREAMBLE):
                preamble = line[:6]
                data = line[6:].strip()
                if preamble == INS_PREAMBLE:
                    num_tests += 1
                if preamble == HDR_PREAMBLE or preamble == INS_PREAMBLE:  # set other shares to zeros
                    line = preamble + data + \
                        ("0" * (num_shares - 1) * len(data)) + "\n"
                    if w_nbytes == 0:
                        w_nbytes = (len(data) + 1) // 2
                elif preamble == DAT_PREAMBLE:
                    data_bytes = bytes.fromhex(data)
                    data_str = ""
                    for i in range(0, len(data_bytes), w_nbytes):
                        word = data_bytes[i:i+w_nbytes]
                        shares = [secrets.token_bytes(
                            w_nbytes) for _ in range(num_shares - 1)]
                        shares.append(reduce(xor, shares + [word]))
                        # assert reduce(xor, shares) == word
                        data_str += "".join([x.hex().upper() for x in shares])
                    line = preamble + data_str + "\n"
            o.write(line)

    print(
        f"Generated {out_file} with {num_tests} tests split into {num_shares} shares from {in_file.name}"
    )


parser.add_argument('--rdi-file', default=None, type=Path,
                    help='path to generated rdi.txt')
parser.add_argument(
    '--pdi-file', default=None, type=argparse.FileType('r'),
    help='path to unshared pdi.txt')
parser.add_argument(
    '--sdi-file', default=None, type=argparse.FileType('r'),
    help='path to unshared sdi.txt')
parser.add_argument('--rdi-width', default=None, required='--rdi-file' in sys.argv, type=int,
                    help='width of RDI data port in bits (RW)')
parser.add_argument('--pdi-width', default=None, type=int,
                    help='width of PDI data port in bits (W)')
parser.add_argument('--sdi-width', default=None, type=int,
                    help='width of SDI data port in bits (SW)')
parser.add_argument('--pdi-shares', default=None, required='--pdi-file' in sys.argv, type=int,
                    help='number of PDI shares')
parser.add_argument('--sdi-shares', default=None, type=int,
                    help='number of SDI shares')
parser.add_argument('--rdi-words', default=200000,
                    type=int, help='number of RDI words')
parser.add_argument('--design', default=None, type=argparse.FileType('r'),
                    help="""TOML description file for the protected LWC design.
                     If provided, all parameters will be extracted from this file.""")

parser.add_argument('--folder', default=None, type=Path,
                    help="""Use this folder containing inputs pdi.txt and sdi.txt.
                     Output files will also be generated under this folder.""")

args = parser.parse_args()

if len(sys.argv) == 1:
    parser.print_help()
    parser.exit()


if args.design:
    try:
        import toml
    except ModuleNotFoundError:
        print("toml package needs to be installed. Try running: 'python3 -m pip install -U toml'")
    design = toml.load(args.design)
    lwc = design.get('lwc', {})
    ports = lwc.get('ports', {})
    pdi = ports.get('pdi', {})
    sdi = ports.get('sdi', {})
    rdi = ports.get('rdi', {})
    args.pdi_width = pdi.get('bit_width', 32)
    args.pdi_shares = pdi.get('num_shares')
    args.sdi_width = sdi.get('bit_width', args.pdi_width)
    args.sdi_shares = sdi.get('num_shares')
    args.rdi_width = rdi.get('bit_width')

if args.folder:
    assert isinstance(args.folder, Path)
    assert args.folder.exists() and args.folder.is_dir(
    ), f"Folder {args.folder} does not exist!"
    if not args.pdi_file:
        args.pdi_file = open(args.folder / "pdi.txt")
    if not args.sdi_file:
        args.sdi_file = open(args.folder / "sdi.txt")

if args.rdi_width and args.pdi_file and not args.rdi_file:
    args.rdi_file = Path(args.pdi_file.name).parent / "rdi.txt"

if args.pdi_file:
    if not args.pdi_shares or args.pdi_shares < 2:
        print("--pdi-shares <N> must be specified and N > 1!")
        exit(1)
    nbytes = 0  # auto
    if args.pdi_width:
        nbytes = (args.pdi_width + 7) // 8
    gen_shares(args.pdi_file, args.pdi_shares, nbytes)

if args.sdi_file:
    if not args.sdi_shares:
        if args.pdi_shares:
            args.sdi_shares = args.pdi_shares
            print(
                f"sdi-shares not specified. Using default value of pdi-shares={args.pdi_shares}")
        else:
            print("--sdi-shares <SN> must be specified and SN >= 1!")
            exit(1)
    nbytes = 0  # auto
    if args.pdi_width:
        nbytes = (args.pdi_width + 7) // 8
    gen_shares(args.sdi_file, args.sdi_shares, nbytes)

if args.rdi_file:
    if not args.rdi_width:
        print("--rdi-width <RW> (RW > 0) must be specified!")
        exit(1)
    rw_bytes = (args.rdi_width + 7) // 8  # round to bytes
    with open(args.rdi_file, "w") as f:
        for i in range(args.rdi_words):
            f.write(secrets.token_hex(rw_bytes).upper() + '\n')
    print(
        f"Generated RDI file: {args.rdi_file.name} RW={args.rdi_width} words={args.rdi_words}")
