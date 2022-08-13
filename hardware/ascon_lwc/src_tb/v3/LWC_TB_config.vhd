--===============================================================================================--
--! @file       LWC_TB_config.vhd
--! @brief      Template for LWC package configuration (LWC_config)
--!
--! @author     Robert Primas <rprimas@proton.me>
--!
--! @copyright  Copyright (c) 2021 IAIK, Graz University of Technology, AUSTRIA
--!             All rights Reserved.
--!
--! @license    This project is released under the GNU Public License.
--!             The license and distribution terms for this file may be
--!             found in the file LICENSE in this distribution or at
--!             http://www.gnu.org/licenses/gpl-3.0.txt                                                     
--!
--===============================================================================================--

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

package LWC_TB_config is

    CONSTANT G_FNAME_PDI : string := "KAT/v3/pdi_shared_3.txt"; -- ! Path to the input file containing cryptotvgen PDI testvector data
    CONSTANT G_FNAME_SDI : string := "KAT/v3/sdi_shared_3.txt"; -- ! Path to the input file containing cryptotvgen SDI testvector data
    CONSTANT G_FNAME_DO  : string := "KAT/v3/do.txt"; -- ! Path to the input file containing cryptotvgen DO testvector data
    CONSTANT G_FNAME_RDI : string := "KAT/v3/rdi.txt"; -- ! Path to the input file containing random data

end package;
