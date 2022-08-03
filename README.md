# NIST LWC Hardware API implementation of Ascon v1.2 with Power Side-Channel Protection

* Hardware Design Group: Institute of Applied Information Processing and Communications, Graz, Austria
* Primary Hardware Designers: Robert Primas (https://rprimas.github.io, rprimas@proton.me), Rishub Nagpal (https://rishub.xyz/, rishub.nagpal 'at' lamarr.at)
* LWC candidate: Ascon

Ascon is a family of authenticated encryption and hashing algorithms designed to be lightweight and easy to implement, even with added countermeasures against side-channel attacks.
Ascon has been selected as the primary choice for lightweight authenticated encryption in the final portfolio of the CAESAR competition (2014-2019) and is currently competing as a finalist in the NIST Lightweight Cryptography competition (2019-). 

## Available Variants

- **v1**: 1st-order DOM
  - Incomplete register layer (updated on falling clk) after first affine layer to avoid glitchy-dependend inputs of indep-DOM-AND gates in the subsequent keccak sbox layer.
  - Incomplete register layer (updated on rising clk) after DOM-compute step to avoid glitch-related issues.
- **v2**: 1st-order DOM.
  - Incomplete register layer (updated on falling clk) after first affine layer to avoid glitchy-dependend inputs of indep-DOM-AND gates in the subsequent keccak sbox layer.
  - Complete register layer (updated on rising clk) after DOM-compute step to avoid glitch-related issues and potentially allow an overall higher maximum clock frequency.
- **v3**: Same as **v1** except with 2nd-order protection level.
- **v4**: Same as **v2** except with 2nd-order protection level.

## Quick Start

* Install LWC testvecor generation scripts:
`pip3 install software/cryptotvgen`
* Compile software reference implementations:
`cryptotvgen --prepare_libs --candidates_dir=software/ascon_ref`
* Install the GHDL open-source VHDL simulator (tested with version 0.37 and 1.0):
`sudo apt install ghdl`
* Execute VHDL testbench for v1 (or other variants):
`cd hardware/ascon_lwc`
`python3 test_v1.py`
`bash test_all.sh`

# TODO add python scripts for ghdl

## Preliminary Security Evaluation

We have successfully formally verified the correctness of our masked implementations of Ascon-p in the glitch-extended probing model and for the respective protection order using the tool Coco (https://www.usenix.org/system/files/sec21fall-gigerl.pdf,https://github.com/IAIK/coco-alma).
