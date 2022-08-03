--===============================================================================================--
--! @file       design_pkg.vhd
--! @brief      Template for CryptoCore design package
--!
--! @author     Michael Tempelmeier <michael.tempelmeier@tum.de>
--! @author     Patrick Karl <patrick.karl@tum.de>
--! @copyright  Copyright (c) 2019 Chair of Security in Information Technology
--!             ECE Department, Technical University of Munich, GERMANY
--!             All rights Reserved.
--! @author     Kamyar Mohajerani
--! @license    This project is released under the GNU Public License.
--!             The license and distribution terms for this file may be
--!             found in the file LICENSE in this distribution or at
--!             http://www.gnu.org/licenses/gpl-3.0.txt
--!
--! @note       Assign values to all constants in the package body. Add any
--!             constants, types, and functions used only by your CryptoCore.
--!
--! @note       Copy this file into your implementation's source directory
--!              and make any required changes to the design-specific copy.
--!
--===============================================================================================--

package design_pkg is
    --!
    --! These parameters are needed by the LWC package implementation.
    --!
    --! Tag size in bits
    constant TAG_SIZE        : natural := 128;
    --! Hash digest size in bits
    constant HASH_VALUE_SIZE : natural := 256;
    --! CryptoCore BDI data width in bits. Supported values: 32, 16, 8
    constant CCW             : natural := 32;
    --! CryptoCore key input width in bits
    constant CCSW            : natural := CCW;
    constant CCRW            : natural := 0;

end design_pkg;
