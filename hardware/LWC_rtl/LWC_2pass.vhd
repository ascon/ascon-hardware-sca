--------------------------------------------------------------------------------
--! @file       LWC_2pass.vhd
--! @brief      LWC_2pass top level file
--! @copyright  Copyright (c) 2021 Cryptographic Engineering Research Group
--!             ECE Department, George Mason University Fairfax, VA, U.S.A.
--!             All rights Reserved.
--! @license    This project is released under the GNU Public License.
--!             The license and distribution terms for this file may be
--!             found in the file LICENSE in this distribution or at
--!             http://www.gnu.org/licenses/gpl-3.0.txt
--! @note       This is publicly available encryption source code that falls
--!             under the License Exception TSU (Technology and software-
--!             unrestricted)
--------------------------------------------------------------------------------
--! Description
--!
--!  LWC top-level entity for two-pass algorithm implementations
--!
--------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.all;

use work.design_pkg.all;
use work.NIST_LWAPI_pkg.all;

entity LWC_2pass is
    port(
        --! Global ports
        clk       : in  std_logic;
        rst       : in  std_logic;
        --! Public data ports
        pdi_data  : in  std_logic_vector(W - 1 downto 0);
        pdi_valid : in  std_logic;
        pdi_ready : out std_logic;
        --! Secret data ports
        sdi_data  : in  std_logic_vector(SW - 1 downto 0);
        sdi_valid : in  std_logic;
        sdi_ready : out std_logic;
        --! Data out ports
        do_data   : out std_logic_vector(W - 1 downto 0);
        do_ready  : in  std_logic;
        do_valid  : out std_logic;
        do_last   : out std_logic;
        --! Tow-pass FIFO interface
        fdi_data  : in  std_logic_vector(W - 1 downto 0);
        fdi_valid : in  std_logic;
        fdi_ready : out std_logic;
        fdo_data  : out std_logic_vector(W - 1 downto 0);
        fdo_valid : out std_logic;
        fdo_ready : in  std_logic
    );
end LWC_2pass;

architecture structure of LWC_2pass is

    --==========================================================================
    --!Cipher
    --==========================================================================
    ------!Pre-Processor to Cipher (Key PISO)
    signal key_cipher_in              : std_logic_vector(CCSW - 1 downto 0);
    signal key_valid_cipher_in        : std_logic;
    signal key_ready_cipher_in        : std_logic;
    ------!Pre-Processor to Cipher (DATA PISO)
    signal bdi_cipher_in              : std_logic_vector(CCW - 1 downto 0);
    signal bdi_valid_cipher_in        : std_logic;
    signal bdi_ready_cipher_in        : std_logic;
    --
    signal bdi_pad_loc_cipher_in      : std_logic_vector(CCW / 8 - 1 downto 0);
    signal bdi_valid_bytes_cipher_in  : std_logic_vector(CCW / 8 - 1 downto 0);
    signal bdi_size_cipher_in         : std_logic_vector(3 - 1 downto 0);
    signal bdi_eot_cipher_in          : std_logic;
    signal bdi_eoi_cipher_in          : std_logic;
    signal bdi_type_cipher_in         : std_logic_vector(4 - 1 downto 0);
    signal decrypt_cipher_in          : std_logic;
    signal hash_cipher_in             : std_logic;
    signal key_update_cipher_in       : std_logic;
    ------!Cipher(DATA SIPO) to Post-Processor
    signal bdo_cipher_out             : std_logic_vector(CCW - 1 downto 0);
    signal bdo_valid_cipher_out       : std_logic;
    signal bdo_ready_cipher_out       : std_logic;
    ------!Cipher to Post-Processor
    signal end_of_block_cipher_out    : std_logic;
    signal bdo_valid_bytes_cipher_out : std_logic_vector(CCW / 8 - 1 downto 0);
    signal bdo_type_cipher_out        : std_logic_vector(4 - 1 downto 0);
    signal msg_auth_valid             : std_logic;
    signal msg_auth_ready             : std_logic;
    signal msg_auth                   : std_logic;
    --==========================================================================

    --==========================================================================
    --!FIFO
    --==========================================================================
    ------!Pre-Processor to FIFO
    signal cmd_FIFO_in        : std_logic_vector(W - 1 downto 0);
    signal cmd_valid_FIFO_in  : std_logic;
    signal cmd_ready_FIFO_in  : std_logic;
    ------!FIFO to Post_Processor
    signal cmd_FIFO_out       : std_logic_vector(W - 1 downto 0);
    signal cmd_valid_FIFO_out : std_logic;
    signal cmd_ready_FIFO_out : std_logic;
    --==========================================================================

begin

    -- Width parameters sanity checks
    -- See 'Implementer’s Guide to Hardware Implementations Compliant with the Hardware API for LWC_2pass', sec. 4.3:
    -- "The following combinations (w, ccw) are supported in the current version
    --   of the Development Package: (32, 32), (32, 16), (32, 8), (16, 16), and (8, 8).
    --   The following combinations (sw, ccsw) are supported: (32, 32), (32, 16),
    --   (32, 8), (16, 16), and (8, 8). However, w and sw must be always the same."

    assert false report "[LWC_2pass] GW=" & integer'image(W) & ", SW=" & integer'image(SW) & ", CCW=" & integer'image(CCW) & ", CCSW=" & integer'image(CCSW) severity note;

    assert ((W = 32 and (CCW = 32 or CCW = 16 or CCW = 8)) or (W = 16 and CCW = 16) or (W = 8 and CCW = 8))
    report "[LWC_2pass] Invalid combination of (G_W, CCW)" severity failure;

    assert ((SW = 32 and (CCSW = 32 or CCSW = 16 or CCSW = 8)) or (SW = 16 and CCSW = 16) or (SW = 8 and CCSW = 8))
    report "[LWC_2pass] Invalid combination of (SW, CCSW)" severity failure;

    -- ASYNC_RSTN notification
    assert not ASYNC_RSTN report "[LWC_2pass] ASYNC_RSTN=True: reset is configured as asynchronous and active-low" severity note;

    Inst_PreProcessor : entity work.PreProcessor

        port map(
            clk             => clk,
            rst             => rst,
            pdi_data        => pdi_data,
            pdi_valid       => pdi_valid,
            pdi_ready       => pdi_ready,
            sdi_data        => sdi_data,
            sdi_valid       => sdi_valid,
            sdi_ready       => sdi_ready,
            key_data        => key_cipher_in,
            key_valid       => key_valid_cipher_in,
            key_ready       => key_ready_cipher_in,
            bdi_data        => bdi_cipher_in,
            bdi_valid       => bdi_valid_cipher_in,
            bdi_ready       => bdi_ready_cipher_in,
            bdi_pad_loc     => bdi_pad_loc_cipher_in,
            bdi_valid_bytes => bdi_valid_bytes_cipher_in,
            bdi_size        => bdi_size_cipher_in,
            bdi_eot         => bdi_eot_cipher_in,
            bdi_eoi         => bdi_eoi_cipher_in,
            bdi_type        => bdi_type_cipher_in,
            decrypt         => decrypt_cipher_in,
            hash            => hash_cipher_in,
            key_update      => key_update_cipher_in,
            cmd_data        => cmd_FIFO_in,
            cmd_valid       => cmd_valid_FIFO_in,
            cmd_ready       => cmd_ready_FIFO_in
        );

    Inst_Cipher : entity work.CryptoCore_2Pass
        port map(
            clk             => clk,
            rst             => rst,
            key             => key_cipher_in,
            key_valid       => key_valid_cipher_in,
            key_ready       => key_ready_cipher_in,
            bdi             => bdi_cipher_in,
            bdi_valid       => bdi_valid_cipher_in,
            bdi_ready       => bdi_ready_cipher_in,
            bdi_pad_loc     => bdi_pad_loc_cipher_in,
            bdi_valid_bytes => bdi_valid_bytes_cipher_in,
            bdi_size        => bdi_size_cipher_in,
            bdi_eot         => bdi_eot_cipher_in,
            bdi_eoi         => bdi_eoi_cipher_in,
            bdi_type        => bdi_type_cipher_in,
            decrypt_in      => decrypt_cipher_in,
            hash_in         => hash_cipher_in,
            key_update      => key_update_cipher_in,
            bdo             => bdo_cipher_out,
            bdo_valid       => bdo_valid_cipher_out,
            bdo_ready       => bdo_ready_cipher_out,
            bdo_type        => bdo_type_cipher_out,
            bdo_valid_bytes => bdo_valid_bytes_cipher_out,
            end_of_block    => end_of_block_cipher_out,
            msg_auth_valid  => msg_auth_valid,
            msg_auth_ready  => msg_auth_ready,
            msg_auth        => msg_auth,
            fdi_data        => fdi_data,
            fdi_valid       => fdi_valid,
            fdi_ready       => fdi_ready,
            fdo_valid       => fdo_valid,
            fdo_ready       => fdo_ready,
            fdo_data        => fdo_data
        );
    Inst_PostProcessor : entity work.PostProcessor
        port map(
            clk             => clk,
            rst             => rst,
            bdo_data        => bdo_cipher_out,
            bdo_valid       => bdo_valid_cipher_out,
            bdo_ready       => bdo_ready_cipher_out,
            bdo_last        => end_of_block_cipher_out,
            bdo_type        => bdo_type_cipher_out,
            bdo_valid_bytes => bdo_valid_bytes_cipher_out,
            cmd_data        => cmd_FIFO_out,
            cmd_valid       => cmd_valid_FIFO_out,
            cmd_ready       => cmd_ready_FIFO_out,
            do_data         => do_data,
            do_valid        => do_valid,
            do_last         => do_last,
            do_ready        => do_ready,
            auth_valid      => msg_auth_valid,
            auth_ready      => msg_auth_ready,
            auth_success    => msg_auth
        );
    Inst_Header_Fifo : entity work.FIFO
        generic map(
            G_W     => W,
            G_DEPTH => 1
        )
        port map(
            clk        => clk,
            rst        => rst,
            din        => cmd_FIFO_in,
            din_valid  => cmd_valid_FIFO_in,
            din_ready  => cmd_ready_FIFO_in,
            dout       => cmd_FIFO_out,
            dout_valid => cmd_valid_FIFO_out,
            dout_ready => cmd_ready_FIFO_out
        );

end structure;
