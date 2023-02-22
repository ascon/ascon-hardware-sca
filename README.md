# NIST LWC Hardware Design of [Ascon v1.2](https://ascon.iaik.tugraz.at) with Protection against Power Side-Channel Attacks

- Hardware Design Group: Institute of Applied Information Processing and Communications, Graz, Austria
- Primary Hardware Designers:
  - Robert Primas (https://rprimas.github.io, rprimas 'at' proton.me),
  - Rishub Nagpal (https://rishub.xyz/, rishub.nagpal 'at' iaik.tugraz.at)
- LWC candidate: Ascon
- LWC Hardware API version: 1.2.0

[Ascon](https://ascon.iaik.tugraz.at) is a family of authenticated encryption and hashing algorithms designed to be lightweight and easy to implement, even with added countermeasures against side-channel attacks. Ascon has been selected as new standard for lightweight cryptography in the [NIST Lightweight Cryptography competition](https://www.nist.gov/news-events/news/2023/02/nist-selects-lightweight-cryptography-algorithms-protect-small-devices) (2019–2023). Ascon has also been selected as the primary choice for lightweight authenticated encryption in the final portfolio of the [CAESAR competition](https://competitions.cr.yp.to/caesar.html) (2014-2019).

The provided protected implementations of Ascon-128 feature Domain-oriented masking (DOM) [[GMK16]](https://eprint.iacr.org/2016/486.pdf) with protection orders 1 and 2. The concrete implementations are inspired by the description of masked Ascon implementation in Section 5 from [[GM17]](https://eprint.iacr.org/2017/103.pdf). All implementations require 2 cycles to compute one permutation round, the masking schemes hence adds one additional cycle of latency per round. Absorption and squeezing happens concurrently for all shares and is hence as fast as in case of unprotected implementations. The throughput of masked implementations is hence increased to 1.75 cycles/byte when using a 32-bit interface (per share). In comparison, a corresponding unprotected implementations achieve a throughput of 1 cycle/byte. The implementations are not optimized for low randomness requirements and hence require the expected 320 bits (960 bits) of fresh randomness every other cycle when computing DOM-AND gates on the 320-bit Ascon state in case of 1st (2nd) order implementations. We want to point out that techniques such as Changing of the Guards [[Dae16]](https://eprint.iacr.org/2016/1061.pdf) could be used to significantly reduce the amount of required fresh randomness. The tag comparison during decryption is currently simply implemented in an unmasked fashion.

The hardware reference implementation of Ascon without countermeasures against power analysis attacks can be found [here](https://github.com/ascon/ascon-hardware).

## Available Variants

- **v1**: Ascon128 with 1st-order DOM.
  - Incomplete register layer (updated on falling clk) after first affine layer to avoid glitchy-dependend inputs of indep-DOM-AND gates in the subsequent keccak sbox layer.
  - Incomplete register layer (updated on rising clk) after DOM-compute step to avoid glitch-related issues.
- **v2**: Ascon128 with 1st-order DOM.
  - Incomplete register layer (updated on falling clk) after first affine layer to avoid glitchy-dependend inputs of indep-DOM-AND gates in the subsequent keccak sbox layer.
  - Complete register layer (updated on rising clk) after DOM-compute step to avoid glitch-related issues and potentially allow an overall higher maximum clock frequency.
- **v3**: Same as **v1** except with 2nd-order protection level.
- **v4**: Same as **v2** except with 2nd-order protection level.

## Folders

- `hardware`: HDL sources and testbench scripts.
- `software`: Software reference implementation and Known-Answer-Test (KAT) generation scripts.

## Quick Start

- Install the GHDL open-source VHDL simulator (tested with version 1.0 and 2.0):
  - `sudo apt install ghdl`
- Execute VHDL testbench for v1 (or other variants):
  - `cd hardware/ascon_lwc`
  - `make v1`

## Generating new Testvectors from Software

- Install testvector generation scripts:
  - `pip3 install software/cryptotvgen`
- Compile Ascon software reference implementations:
  - `cryptotvgen --prepare_libs --candidates_dir=software/ascon_ref`
- Locate testvector generation scripts:
  - `cd software/cryptotvgen/examples`
- Run (and optionally modify) a testvector generation script:
  - `python genkat.py`
- Replace existing testvectors (KAT) of v1 with the newly generated ones:
  - `mv testvectors/ascon128v12_32 testvectors/v1`
  - `rm -r ../../../hardware/ascon_lwc/KAT/v1`
  - `mv testvectors/v1 ../../../hardware/ascon_lwc/KAT`
- Generate masked KAT files from the unmasked ones:
  - `cd ../../../hardware/ascon_lwc`
  - `python gen_shared.py --design ascon_v1.toml --folder ./KAT/v1`
- Execute VHDL testbench for v1:
  - `make v1`

## Preliminary Security Evaluation

A previous version of this masked hardware design of Ascon (see `ASCON_IAIK_OLD.zip`) was submitted to the [Call for Protected Hardware Implementations](https://cryptography.gmu.edu/athena/LWC/Call_for_Protected_Hardware_Implementations.pdf) of the NIST standardization effort for Lightweight Cryptography. Several side-channel evaluation labs have since evalauted it's protection against Differential Power Analysis. The results are available [here]( https://cryptography.gmu.edu/athena/index.php?id=LWC).

We have also successfully formally verified the correctness of the masked implementation of Ascon-*p* in `ASCON_IAIK_OLD.zip` in the glitch-extended probing model (aka robust probing model) and for the respective protection order using the tool Coco [[GHP+21]](https://www.usenix.org/system/files/sec21fall-gigerl.pdf).

## Acknowledgements

This code base is based on version 1.2.0 of the [LWC Hardware API Development Package](https://github.com/GMUCERG/LWC) that was mainly developed by the Cryptographic Engineering Research Group [(CERG)](https://cryptography.gmu.edu) at George Mason University (GMU).

Parts of the development package have been developed by the Department of Electrical and Computer Engineering [(ECE)](https://www.ei.tum.de/en/ei/welcome/) at Technical University of Munich (TUM).

The Ascon-specific modifications have been developed by the Institute of Applied Information Processing and Communications [(IAIK)](https://iaik.tugraz.at/) at Graz University of Technology (TUG).

