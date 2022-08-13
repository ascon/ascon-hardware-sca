--------------------------------------------------------------------------------
--! @file       design_pkg.vhd
--! @brief      Package for the Crypto Core.
--!
--! @author     Robert Primas <rprimas@proton.me>
--!
--! @author     Rishub Nagpal <rishub.nagpal@lamarr.at>
--!
--! @copyright  Copyright (c) 2021 IAIK, Graz University of Technology, AUSTRIA
--!             All rights Reserved.
--!
--! @license    This project is released under the GNU Public License.
--!             The license and distribution terms for this file may be
--!             found in the file LICENSE in this distribution or at
--!             http://www.gnu.org/licenses/gpl-3.0.txt
--!
--! @note       This code was adapted for the Ascon AEAD scheme.                                                        
-------------------------------------------------------------------------------


library IEEE;
use IEEE.STD_LOGIC_1164.all;
use work.LWC_config;

package design_pkg is

    --! design parameters specific to the CryptoCore
    constant D : integer := LWC_config.PDI_SHARES - 1;
    constant UROL : INTEGER RANGE 0 TO 4 := 1;

    --! declaration of crypto core design parameters
    CONSTANT IV_AEAD : std_logic_vector(63 DOWNTO 0);
    CONSTANT ROUNDS_A : std_logic_vector(7 DOWNTO 0);
    CONSTANT ROUNDS_B : std_logic_vector(7 DOWNTO 0);

    --! design parameters needed by the PreProcessor, PostProcessor, and LWC
    --!
    --! Tag size in bits
    constant TAG_SIZE        : integer := 128;
    --! Hash digest size in bits
    constant HASH_VALUE_SIZE : integer := 256;
    --! CryptoCore BDI data width in bits. Supported values: 32, 16, 8
    constant CCW             : integer := 32;
    --! CryptoCore key input width in bits
    constant CCSW            : integer := CCW;
    --!
    constant CCRW            : integer := 0;

    --===========================================================================================--

    --! Adjust the bit counter widths to reduce resource consumption.
    -- Range definition must not change.
    constant AD_CNT_WIDTH    : integer range 4 to 64 := 32;  --! Width of AD Bit counter
    constant MSG_CNT_WIDTH   : integer range 4 to 64 := 32;  --! Width of MSG (PT/CT) Bit counter todo remove?

--------------------------------------------------------------------------------
------------------------- DO NOT CHANGE ANYTHING BELOW -------------------------
--------------------------------------------------------------------------------
    
    --! design parameters specific to the CryptoCore; assigned in the package body below!
    --! place declarations of your constants here
    constant NPUB_SIZE       : integer; --! Npub size
    constant DBLK_SIZE       : integer; --! Block size
    
    constant CCWdiv8         : integer; --! derived from parameters above, assigned in body.
    
    --! place declarations of your functions here
    --! Calculate the number of I/O words for a particular size
    function get_words(size: integer; iowidth:integer) return integer; 
    
    --! Reverse the Byte order of the input word.
    function reverse_byte( vec : std_logic_vector ) return std_logic_vector;
    --! Reverse the Bit order of the input vector.
    function reverse_bit( vec : std_logic_vector ) return std_logic_vector;
    --! Padding the current word.
    function pad_bdi(bdi, bdi_valid_bytes, bdi_pad_loc, state_word : std_logic_vector; pt_ct : std_logic) return std_logic_vector;
    --! Return max value
    function max( a, b : integer) return integer;

    type shared_lane_t is array(NATURAL range <>) of std_logic_vector(63 downto 0);
    
    type shared_state2_t is array(D downto 0) of std_logic_vector(319 downto 0);
    type shared_key2_t is array(D downto 0) of std_logic_vector(127 downto 0);
    type shared_word2_t is array(D downto 0) of std_logic_vector(31 downto 0);
    
    type shared_state_t is array(natural range <>) of shared_lane_t(D downto 0);
    -- type shared_t is array(natural range <>) of std_logic_vector;
    type random_shares_t is array (((D*(D+1))/2) - 1 downto 0) of std_logic_vector(319 downto 0);
    type random_shares2_t is array (4 downto 0) of shared_lane_t(((D*(D+1))/2) - 1 downto 0);

    -- State signals
    TYPE state_t IS (
        IDLE,
        STORE_KEY,
        STORE_NONCE,
        INIT_STATE_SETUP,
        -- AEAD
        INIT_PROCESS,
        INIT_KEY_ADD,
        ABSORB_AD,
        PROCESS_AD,
        PAD_AD,
        DOM_SEP,
        ABSORB_MSG,
        PROCESS_MSG,
        PAD_MSG,
        FINAL_KEY_ADD_1,
        FINAL_PROCESS,
        FINAL_KEY_ADD_2,
        EXTRACT_TAG,
        VERIFY_TAG,
        WAIT_ACK
    );
        
    function dyn_slice(
        paddy : std_logic_vector;
        bdi_eot,bdi_partial_s : std_logic;
        ascon_state_s : shared_state2_t;
        word_idx_s : integer
    ) return shared_state2_t;

end package;


package body design_pkg is

    ---------------------------------------------------------------------------
    --                              _ ____  ___  
    --   __ _ ___  ___ ___  _ __   / |___ \( _ ) 
    --  / _` / __|/ __/ _ \| '_ \  | | __) / _ \ 
    -- | (_| \__ \ (_| (_) | | | | | |/ __/ (_) |
    --  \__,_|___/\___\___/|_| |_| |_|_____\___/ 
    -- v1,v3,v5: ascon128v12                     
    ---------------------------------------------------------------------------
    CONSTANT IV_AEAD : std_logic_vector(63 DOWNTO 0) := X"80400c0600000000";
    CONSTANT ROUNDS_A : std_logic_vector(7 DOWNTO 0) := X"18";
    CONSTANT ROUNDS_B : std_logic_vector(7 DOWNTO 0) := X"0C";
    CONSTANT DBLK_SIZE : INTEGER := 64;
    constant NPUB_SIZE : integer := 128;  --! Npub size

    -----------------------------------------------------------------------------
    --                              _ ____  ___        
    --   __ _ ___  ___ ___  _ __   / |___ \( _ )  __ _ 
    --  / _` / __|/ __/ _ \| '_ \  | | __) / _ \ / _` |
    -- | (_| \__ \ (_| (_) | | | | | |/ __/ (_) | (_| |
    --  \__,_|___/\___\___/|_| |_| |_|_____\___/ \__,_|
    -- v2,v4,v6: ascon128av12                          
    -----------------------------------------------------------------------------
    -- CONSTANT IV_AEAD : std_logic_vector(63 DOWNTO 0) := X"80800c0800000000";
    -- CONSTANT ROUNDS_A : std_logic_vector(7 DOWNTO 0) := X"0C";
    -- CONSTANT ROUNDS_B : std_logic_vector(7 DOWNTO 0) := X"08";
    -- CONSTANT DBLK_SIZE : integer := 128;

    constant CCWdiv8 : integer := CCW / 8;

    --! define your functions here
    --! Calculate the number of words
    function get_words(size: integer; iowidth:integer) return integer is
    begin
        if (size mod iowidth) > 0 then
            return size/iowidth + 1;
        else
            return size/iowidth;
        end if;
    end function get_words;

   --! Reverse the Byte order of the input word.
    function reverse_byte( vec : std_logic_vector ) return std_logic_vector is
        variable res : std_logic_vector(vec'length - 1 downto 0);
        constant n_bytes  : integer := vec'length/8;
    begin

        -- Check that vector length is actually byte aligned.
        assert (vec'length mod 8 = 0)
            report "Vector size must be in multiple of Bytes!" severity failure;

        -- Loop over every byte of vec and reorder it in res.
        for i in 0 to (n_bytes - 1) loop
            res(8*(i+1) - 1 downto 8*i) := vec(8*(n_bytes - i) - 1 downto 8*(n_bytes - i - 1));
        end loop;

        return res;
    end function reverse_byte;

    --! Reverse the Bit order of the input vector.
    function reverse_bit( vec : std_logic_vector ) return std_logic_vector is
        variable res : std_logic_vector(vec'length - 1 downto 0);
    begin

        -- Loop over every bit in vec and reorder it in res.
        for i in 0 to (vec'length - 1) loop
            res(i) := vec(vec'length - i - 1);
        end loop;

        return res;
    end function reverse_bit;

    --! Padd the data with 0x80 Byte if pad_loc is set.
    function pad_bdi( bdi, bdi_valid_bytes, bdi_pad_loc, state_word : std_logic_vector; pt_ct : std_logic) return std_logic_vector is
        variable res : std_logic_vector(bdi'length - 1 downto 0) := state_word;
    begin
        for i in 0 to (bdi_valid_bytes'length - 1) loop
            if (bdi_valid_bytes(i) = '1') then
                if (pt_ct = '0') then
                    for s in 0 to D loop
                        res(CCW*s + 8*(i+1) - 1 downto CCW*s + 8*i) := res(CCW*s + 8*(i+1) - 1 downto CCW*s + 8*i) XOR bdi(CCW*s + 8*(i+1) - 1 downto CCW*s + 8*i);
                    end loop;
                else
                    for s in 0 to D loop
                        res(CCW*s + 8*(i+1) - 1 downto CCW*s + 8*i) := bdi(CCW*s + 8*(i+1) - 1 downto CCW*s + 8*i);
                    end loop;
                end if;
            elsif (bdi_pad_loc(i) = '1') then
                for s in 0 to D loop
                    if s = D then
                        res(CCW*s + 8*(i+1) - 1 downto CCW*s + 8*i) := res(CCW*s + 8*(i+1) - 1 downto CCW*s + 8*i) XOR x"80";
                    else
                        res(CCW*s + 8*(i+1) - 1 downto CCW*s + 8*i) := res(CCW*s + 8*(i+1) - 1 downto CCW*s + 8*i);
                    end if;
                end loop;
            end if;
        end loop;
        return res;
    end function;


    function dyn_slice(paddy : std_logic_vector; bdi_eot, bdi_partial_s : std_logic; ascon_state_s : shared_state2_t; word_idx_s : integer) return shared_state2_t is
        variable res : shared_state2_t := ascon_state_s;
        variable last_word_idx : integer RANGE 0 TO DBLK_SIZE/CCW-1;
    begin
        last_word_idx := DBLK_SIZE/CCW-1;
        
--        res(word_idx_s*CCW+CCW-1 downto word_idx_s*CCW) := paddy;
        for s in 0 to D loop
            res(s)(word_idx_s*CCW + CCW - 1 downto word_idx_s*CCW) := paddy(CCW*s + CCW - 1 downto CCW*s);
        end loop;
        
        IF (word_idx_s < (last_word_idx) and bdi_eot = '1' and bdi_partial_s = '0' ) THEN
--            res(word_idx_s*CCW+CCW+7 downto word_idx_s*CCW+CCW) := res(word_idx_s*CCW+CCW+7 downto word_idx_s*CCW+CCW) XOR X"80";
              res(D)(word_idx_s*CCW+CCW+7 downto word_idx_s*CCW+CCW) := res(D)(word_idx_s*CCW+CCW+7 downto word_idx_s*CCW+CCW) XOR X"80";
        END IF;
        
        return res;
    end function;

    --! Return max value.
    function max( a, b : integer) return integer is
    begin
        if (a >= b) then
            return a;
        else
            return b;
        end if;
    end function;

end package body design_pkg;
