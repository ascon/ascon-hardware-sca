--------------------------------------------------------------------------------
--! @file       CryptoCore.vhd
--! @brief      Implementation of Ascon-128, Ascon-128a and Ascon-Hash.
--!
--! @author     Robert Primas <rprimas@protonmail.com>, Rishub Nagpal <rishub.nagpal@lamarr.at>
--! @copyright  Copyright (c) 2020 IAIK, Graz University of Technology, AUSTRIA
--!             All rights Reserved.
--! @license    This project is released under the GNU Public License.          
--!             The license and distribution terms for this file may be         
--!             found in the file LICENSE in this distribution or at            
--!             http://www.gnu.org/licenses/gpl-3.0.txt                         
--! @note       This is publicly available encryption source code that falls    
--!             under the License Exception TSU (Technology and software-       
--!             unrestricted)                                                  
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
--   ____                  _           ____               
--  / ___|_ __ _   _ _ __ | |_ ___    / ___|___  _ __ ___ 
-- | |   | '__| | | | '_ \| __/ _ \  | |   / _ \| '__/ _ \
-- | |___| |  | |_| | |_) | || (_) | | |__| (_) | | |  __/
--  \____|_|   \__, | .__/ \__\___/   \____\___/|_|  \___|
--	           |___/|_|                                   
--                                                        
--------------------------------------------------------------------------------

LIBRARY ieee;
USE ieee.std_logic_1164.ALL;
USE ieee.numeric_std.ALL;
USE ieee.std_logic_misc.ALL;
USE work.NIST_LWAPI_pkg.ALL;
USE work.design_pkg.ALL;

ENTITY CryptoCore_SCA IS
    PORT (
        clk : IN STD_LOGIC;
        rst : IN STD_LOGIC;
        --
        key : IN STD_LOGIC_VECTOR(SDI_SHARES * CCSW - 1 DOWNTO 0);
        key_valid : IN STD_LOGIC;
        key_ready : OUT STD_LOGIC;
        --
        key_update : IN STD_LOGIC;
        --
        bdi : IN STD_LOGIC_VECTOR(PDI_SHARES * CCW - 1 DOWNTO 0);
        bdi_valid : IN STD_LOGIC;
        bdi_ready : OUT STD_LOGIC;
        bdi_pad_loc : IN STD_LOGIC_VECTOR(CCW / 8 - 1 DOWNTO 0);
        bdi_valid_bytes : IN STD_LOGIC_VECTOR(CCW / 8 - 1 DOWNTO 0);
        bdi_size : IN STD_LOGIC_VECTOR(3 - 1 DOWNTO 0);
        bdi_eot : IN STD_LOGIC;
        bdi_eoi : IN STD_LOGIC;
        bdi_type : IN STD_LOGIC_VECTOR(4 - 1 DOWNTO 0);
        --
        decrypt_in : IN STD_LOGIC;
        hash_in : IN STD_LOGIC;
        --
        bdo : OUT STD_LOGIC_VECTOR(PDI_SHARES * CCW - 1 DOWNTO 0);
        bdo_valid : OUT STD_LOGIC;
        bdo_ready : IN STD_LOGIC;
        bdo_type : OUT STD_LOGIC_VECTOR(4 - 1 DOWNTO 0);
        bdo_valid_bytes : OUT STD_LOGIC_VECTOR(CCW / 8 - 1 DOWNTO 0);
        --
        end_of_block : OUT STD_LOGIC;
        --
        msg_auth_valid : OUT STD_LOGIC;
        msg_auth_ready : IN STD_LOGIC;
        msg_auth : OUT STD_LOGIC;
        --
        rdi : IN STD_LOGIC_VECTOR(((D * (D + 1))/2) * 320 - 1 DOWNTO 0);
        rdi_valid : IN STD_LOGIC;
        rdi_ready : OUT STD_LOGIC
    );
END CryptoCore_SCA;

ARCHITECTURE behavioral OF CryptoCore_SCA IS

    ---------------------------------------------------------------------------
    --! Constant Values: Ascon
    ---------------------------------------------------------------------------
    CONSTANT TAG_SIZE : INTEGER := 128;
    CONSTANT stateIZE : INTEGER := 320;
    CONSTANT IV_SIZE : INTEGER := 64;
    CONSTANT NPUB_SIZE : INTEGER := 128;
    CONSTANT DBLK_HASH_SIZE : INTEGER := 64;
    CONSTANT KEY_SIZE : INTEGER := 128;

    --! Constant to check for empty hash
    CONSTANT EMPTY_HASH_SIZE_C : STD_LOGIC_VECTOR(2 DOWNTO 0) := (OTHERS => '0');

    -- Number of words the respective blocks contain.
    CONSTANT NPUB_WORDS_C : INTEGER := get_words(NPUB_SIZE, CCW);
    CONSTANT HASH_WORDS_C : INTEGER := get_words(HASH_VALUE_SIZE, CCW);
    CONSTANT BLOCK_WORDS_C : INTEGER := get_words(DBLK_SIZE, CCW);
    CONSTANT BLOCK_HASH_WORDS_C : INTEGER := get_words(DBLK_HASH_SIZE, CCW);
    CONSTANT KEY_WORDS_C : INTEGER := get_words(KEY_SIZE, CCW);
    CONSTANT TAG_WORDS_C : INTEGER := get_words(TAG_SIZE, CCW);

    SIGNAL n_state, state : state_t;

    -- Selection signal of the current word
    SIGNAL word_idx : INTEGER RANGE 0 TO HASH_WORDS_C - 1; -- todo check ranges
    SIGNAL word_idx_offset_s : INTEGER RANGE 0 TO HASH_WORDS_C - 1;

    -- Internal Port signals
    SIGNAL key_s : STD_LOGIC_VECTOR(SDI_SHARES * CCSW - 1 DOWNTO 0);
    SIGNAL bdi_s : STD_LOGIC_VECTOR(PDI_SHARES * CCW - 1 DOWNTO 0);
    SIGNAL bdi_valid_bytes_s : STD_LOGIC_VECTOR(CCWdiv8 - 1 DOWNTO 0);
    SIGNAL bdi_pad_loc_s : STD_LOGIC_VECTOR(CCWdiv8 - 1 DOWNTO 0);
    SIGNAL bdo_s : STD_LOGIC_VECTOR(PDI_SHARES * CCW - 1 DOWNTO 0);
    SIGNAL bdo_valid_bytes_s : STD_LOGIC_VECTOR(CCWdiv8 - 1 DOWNTO 0);
    SIGNAL bdoo_s : STD_LOGIC_VECTOR(PDI_SHARES * CCW - 1 DOWNTO 0);

    -- Internal Flags
    SIGNAL n_decrypt, decrypt : STD_LOGIC;
    SIGNAL n_hash, hash : STD_LOGIC;
    SIGNAL n_empty_hash, empty_hash : STD_LOGIC;
    SIGNAL n_msg_auth: STD_LOGIC;
    SIGNAL n_eoi, eoi : STD_LOGIC;
    SIGNAL n_eot, eot : STD_LOGIC;
    SIGNAL n_update_key, update_key : STD_LOGIC;

    -- Utility Signals
    SIGNAL bdi_partial : STD_LOGIC;
    SIGNAL pad_added : STD_LOGIC;

    -- Ascon Signals
    SIGNAL ascon_state : shared_state2_t;
    SIGNAL ascon_state_n_s : shared_state2_t;
    SIGNAL ascon_cnt_s : STD_LOGIC_VECTOR(7 DOWNTO 0);
    SIGNAL ascon_key_s : shared_key2_t;
    SIGNAL ascon_rcon_s : STD_LOGIC_VECTOR(3 DOWNTO 0);

    -- Ascon-p
    SIGNAL asconp_out_s : shared_state2_t;
    SIGNAL rdi_s : shared_word2_t;

    -- Debug Signals (unmasked)
    SIGNAL debug_pad1_s : STD_LOGIC_VECTOR(CCW - 1 DOWNTO 0);
    SIGNAL debug_bdoo_s : STD_LOGIC_VECTOR(CCW - 1 DOWNTO 0);
    SIGNAL debug_bdi_s : STD_LOGIC_VECTOR(CCW - 1 DOWNTO 0);
    SIGNAL debug_ascon_key_s : STD_LOGIC_VECTOR(128 - 1 DOWNTO 0);
    SIGNAL debug_ascon_s : STD_LOGIC_VECTOR(stateIZE - 1 DOWNTO 0);
    SIGNAL debug_ascon_n_s : STD_LOGIC_VECTOR(stateIZE - 1 DOWNTO 0);
    SIGNAL debug_asconp_s : STD_LOGIC_VECTOR(stateIZE - 1 DOWNTO 0);

    FUNCTION combine_shares(x : STD_LOGIC_VECTOR) RETURN STD_LOGIC_VECTOR IS
        VARIABLE len : INTEGER := x'length/PDI_SHARES;
        VARIABLE result : STD_LOGIC_VECTOR(len - 1 DOWNTO 0) := (OTHERS => '0');
    BEGIN
        FOR s IN 0 TO D LOOP
            result := result XOR x(len * s + len - 1 DOWNTO len * s);
        END LOOP;
        RETURN result;
    END FUNCTION combine_shares;

    FUNCTION combine_shares_k(x : shared_key2_t) RETURN STD_LOGIC_VECTOR IS
        VARIABLE result : STD_LOGIC_VECTOR(x(0)'length - 1 DOWNTO 0);
    BEGIN
        result := (OTHERS => '0');
        FOR s IN 0 TO D LOOP
            result := result XOR x(s);
        END LOOP;
        RETURN result;
    END FUNCTION combine_shares_k;

    FUNCTION combine_shares(x : shared_state2_t) RETURN STD_LOGIC_VECTOR IS
        VARIABLE result : STD_LOGIC_VECTOR(x(0)'length - 1 DOWNTO 0);
    BEGIN
        result := (OTHERS => '0');
        FOR share IN 0 TO D LOOP
            result := result XOR x(share);
        END LOOP;
        RETURN result;
    END FUNCTION combine_shares;

BEGIN

    ---------------------------------------------------------------------------
    --! Debug Signals
    ---------------------------------------------------------------------------

    debug_bdi_s <= reverse_byte(combine_shares(bdi_s));
    debug_bdoo_s <= reverse_byte(combine_shares(bdoo_s));
    debug_ascon_key_s <= reverse_byte(combine_shares_k(ascon_key_s));
    debug_ascon_s <= reverse_byte(combine_shares(ascon_state));
    debug_ascon_n_s <= reverse_byte(combine_shares(ascon_state_n_s));
    debug_asconp_s <= reverse_byte(combine_shares(asconp_out_s));

    ----------------------------------------------------------------------------
    -- I/O Mappings
    -- Algorithm is specified in Big Endian. However, this is a Little Endian
    -- implementation so reverse_byte/bit functions are used to reorder affected signals.
    ----------------------------------------------------------------------------

    key_s <= reverse_byte(key);
    bdi_s <= reverse_byte(bdi);
    bdi_valid_bytes_s <= reverse_bit(bdi_valid_bytes);
    bdi_pad_loc_s <= reverse_bit(bdi_pad_loc);
    bdo <= reverse_byte(bdo_s);
    bdo_valid_bytes <= reverse_bit(bdo_valid_bytes_s);

    ---------------------------------------------------------------------------
    --! Utility Signals
    ---------------------------------------------------------------------------

    -- Used to determine whether 0x80 padding word can be inserted into this last word.
    bdi_partial <= or_reduce(bdi_pad_loc_s);

    -- Round constant for Ascon-p.
    ascon_rcon_s <= ascon_cnt_s(4 DOWNTO 1);

    ---------------------------------------------------------------------------
    --! Ascon-p instantiation
    ---------------------------------------------------------------------------

    i_asconp : ENTITY work.asconp
        PORT MAP(
            clk => clk,
            rst => rst,
            state_in => ascon_state,
            rcon => ascon_rcon_s,
            n_state => n_state,
            rdi => rdi,
            rdi_valid => rdi_valid,
            rdi_ready => rdi_ready,
            state_out => asconp_out_s
        );

    -- bdo dynamic slicing
    p_dynslice_bdo : PROCESS (word_idx, ascon_state, word_idx_offset_s)
        VARIABLE sel : INTEGER RANGE 0 TO 10 - 1;
    BEGIN
        sel := word_idx + word_idx_offset_s;
        FOR i IN 0 TO D LOOP
            bdoo_s(CCW * i + CCW - 1 DOWNTO CCW * i) <= ascon_state(i)(CCW * sel + CCW - 1 DOWNTO CCW * sel);
        END LOOP;
    END PROCESS;

    -- bdi dynamic slicing
    p_dynslice_bdi : PROCESS (word_idx, ascon_state, word_idx_offset_s, state, bdi_s, decrypt, bdi_valid_bytes_s, bdi_pad_loc_s, bdoo_s, bdi_eot, bdi_partial)
        VARIABLE pad1 : STD_LOGIC_VECTOR(PDI_SHARES * CCW - 1 DOWNTO 0);
        VARIABLE pad2 : STD_LOGIC_VECTOR(PDI_SHARES * CCW - 1 DOWNTO 0);
    BEGIN
        pad1 := pad_bdi(bdi_s, bdi_valid_bytes_s, bdi_pad_loc_s, bdoo_s, '0');
        pad2 := pad_bdi(bdi_s, bdi_valid_bytes_s, bdi_pad_loc_s, bdoo_s, decrypt);
        debug_pad1_s <= reverse_byte(combine_shares(pad1));
        CASE state IS
            WHEN ABSORB_AD =>
                ascon_state_n_s <= dyn_slice(pad1, bdi_eot, bdi_partial, ascon_state, word_idx);
            WHEN ABSORB_MSG =>
                ascon_state_n_s <= dyn_slice(pad2, bdi_eot, bdi_partial, ascon_state, word_idx);
            WHEN OTHERS =>
                ascon_state_n_s <= ascon_state;
        END CASE;
    END PROCESS;

    -- Word idx offset process
    asdf_CASE : PROCESS (word_idx, state)
    BEGIN
        word_idx_offset_s <= 0;
        CASE state IS
            WHEN EXTRACT_TAG | VERIFY_TAG =>
                word_idx_offset_s <= 6;
            WHEN OTHERS =>
                NULL;
        END CASE;
    END PROCESS;

    ----------------------------------------------------------------------------
    --! Bdo multiplexer
    ----------------------------------------------------------------------------
    bdo_mux : PROCESS (state, bdi_s, word_idx, bdi_ready,
        bdi_valid_bytes_s, bdi_valid, bdi_eot, decrypt, ascon_state,
        hash, bdoo_s)
    BEGIN

        -- Directly connect bdi and bdo signals and encryp/decrypt data.
        -- No default values so each signal requires an assignment in each case.
        CASE state IS

            WHEN ABSORB_MSG =>
                bdo_s <= bdoo_s XOR bdi_s;
                bdo_valid_bytes_s <= bdi_valid_bytes_s;
                bdo_valid <= bdi_ready;
                end_of_block <= bdi_eot;
                IF (decrypt = '1') THEN
                    bdo_type <= HDR_PT;
                ELSE
                    bdo_type <= HDR_CT;
                END IF;

            WHEN EXTRACT_TAG =>
                bdo_s <= bdoo_s;
                bdo_valid_bytes_s <= (OTHERS => '1');
                bdo_valid <= '1';
                bdo_type <= HDR_TAG;
                IF (word_idx = TAG_WORDS_C - 1) THEN
                    end_of_block <= '1';
                ELSE
                    end_of_block <= '0';
                END IF;

            WHEN OTHERS =>
                bdo_s <= (OTHERS => '0');
                bdo_valid_bytes_s <= (OTHERS => '0');
                bdo_valid <= '0';
                end_of_block <= '0';
                bdo_type <= (OTHERS => '0');

        END CASE;
    END PROCESS bdo_mux;

    ----------------------------------------------------------------------------
    --! Registers for state and internal signals
    ----------------------------------------------------------------------------
    p_reg : PROCESS (clk)
    BEGIN
        IF rising_edge(clk) THEN
            IF (rst = '1') THEN
                msg_auth <= '1';
                eoi <= '0';
                eot <= '0';
                update_key <= '0';
                decrypt <= '0';
                hash <= '0';
                empty_hash <= '0';
                state <= IDLE;
            ELSE
                msg_auth <= n_msg_auth;
                eoi <= n_eoi;
                eot <= n_eot;
                update_key <= n_update_key;
                decrypt <= n_decrypt;
                hash <= n_hash;
                empty_hash <= n_empty_hash;
                state <= n_state;
            END IF;
        END IF;
    END PROCESS p_reg;

    ----------------------------------------------------------------------------
    --! Next_state FSM
    ----------------------------------------------------------------------------
    p_next_state : PROCESS (state, key_valid, key_ready, key_update, bdi_valid,
        bdi_ready, bdi_eot, bdi_eoi, eoi, eot, bdi_type, bdi_pad_loc_s,
        word_idx, hash_in, decrypt, bdo_valid, bdo_ready,
        msg_auth_valid, msg_auth_ready, bdi_partial, ascon_cnt_s, hash, pad_added, bdi_ready)
    BEGIN

        -- Default values preventing latches
        n_state <= state;

        CASE state IS

            WHEN IDLE =>
                -- Wakeup as soon as valid bdi or key is signaled.
                IF (key_valid = '1' OR bdi_valid = '1') THEN
                    n_state <= STORE_KEY;
                END IF;

            WHEN STORE_KEY =>
                -- Wait until the new key is received.
                -- It is assumed that key is only updated if Npub follows.
                IF (((key_valid = '1' AND key_ready = '1') OR key_update = '0') AND word_idx >= KEY_WORDS_C - 1) THEN -- todo remove idle cycles
                    n_state <= STORE_NONCE;
                END IF;

            WHEN STORE_NONCE =>
                -- Wait until the whole nonce block is received.
                IF (bdi_valid = '1' AND bdi_ready = '1' AND word_idx >= NPUB_WORDS_C - 1) THEN
                    n_state <= INIT_STATE_SETUP;
                END IF;

            WHEN INIT_STATE_SETUP =>
                n_state <= INIT_PROCESS;

            WHEN INIT_PROCESS =>
                -- After state initialization jump to aead or hash routine.
                IF (ascon_cnt_s = STD_LOGIC_VECTOR(to_unsigned(UROL, ascon_cnt_s'length))) THEN
                    n_state <= INIT_KEY_ADD;
                END IF;

            WHEN INIT_KEY_ADD =>
                -- If ad length is zero then domain seperation follows directly after.
                IF (eoi = '1') THEN
                    n_state <= DOM_SEP;
                ELSE
                    n_state <= ABSORB_AD;
                END IF;

            WHEN ABSORB_AD =>
                -- Absorb and process ad then perform domain seperation.
                IF (bdi_valid = '1' AND bdi_type /= HDR_AD) THEN
                    n_state <= DOM_SEP;
                ELSIF (bdi_valid = '1' AND bdi_ready = '1' AND (bdi_eot = '1' OR word_idx >= BLOCK_WORDS_C - 1)) THEN
                    n_state <= PROCESS_AD;
                END IF;

            WHEN PROCESS_AD =>
                -- Absorb ad blocks until rate is reached or end of type is signaled.
                -- Then check whether padding is necessary or not.
                IF (ascon_cnt_s = STD_LOGIC_VECTOR(to_unsigned(UROL, ascon_cnt_s'length))) THEN
                    IF (pad_added = '0') THEN
                        IF (eot = '1') THEN
                            n_state <= PAD_AD;
                        ELSE
                            n_state <= ABSORB_AD;
                        END IF;
                    ELSE
                        n_state <= DOM_SEP;
                    END IF;
                END IF;

            WHEN PAD_AD =>
                -- Absorb empty block with padding.
                n_state <= PROCESS_AD;

            WHEN DOM_SEP =>
                -- Perform domain separation.
                -- If there is no more input absorb empty block with padding.
                IF (eoi = '1') THEN
                    n_state <= PAD_MSG;
                ELSE
                    n_state <= ABSORB_MSG;
                END IF;

            WHEN ABSORB_MSG =>
                -- Absorb msb blocks until rate is reached or end of type is signaled.
                -- Then check whether padding is necessary or not.
                IF (bdi_ready = '1') THEN
                    IF (eoi = '1') THEN
                        n_state <= FINAL_KEY_ADD_1;
                    ELSE
                        IF (bdi_eot = '1') THEN
                            IF (word_idx < BLOCK_WORDS_C - 1 OR bdi_partial = '1') THEN
                                n_state <= FINAL_KEY_ADD_1;
                            ELSE
                                n_state <= PROCESS_MSG;
                            END IF;
                        ELSIF (word_idx >= BLOCK_WORDS_C - 1) THEN
                            n_state <= PROCESS_MSG;
                        END IF;
                    END IF;
                END IF;

            WHEN PROCESS_MSG =>
                -- Process state after absorbing msg block.
                IF (ascon_cnt_s = STD_LOGIC_VECTOR(to_unsigned(UROL, ascon_cnt_s'length))) THEN
                    IF (eoi = '1') THEN
                        n_state <= PAD_MSG;
                    ELSE
                        n_state <= ABSORB_MSG;
                    END IF;
                END IF;

            WHEN PAD_MSG =>
                -- Absorb empty block with padding.
                n_state <= FINAL_KEY_ADD_1;

            WHEN FINAL_KEY_ADD_1 =>
                -- Second to last key addition.
                n_state <= FINAL_PROCESS;

            WHEN FINAL_PROCESS =>
                -- Process state during finalization.
                IF (ascon_cnt_s = STD_LOGIC_VECTOR(to_unsigned(UROL, ascon_cnt_s'length))) THEN
                    n_state <= FINAL_KEY_ADD_2;
                END IF;

            WHEN FINAL_KEY_ADD_2 =>
                -- After last key addition, either verify or extract the tag.
                IF (decrypt = '1') THEN
                    n_state <= VERIFY_TAG;
                ELSE
                    n_state <= EXTRACT_TAG;
                END IF;

            WHEN EXTRACT_TAG =>
                -- Wait until the whole tag block is transferred, then go back to IDLE.
                IF (bdo_valid = '1' AND bdo_ready = '1' AND word_idx >= TAG_WORDS_C - 1) THEN
                    n_state <= IDLE;
                END IF;

            WHEN VERIFY_TAG =>
                -- Wait until the tag being verified is received, continue
                -- with waiting for acknowledgement on msg_auth_valis.
                IF (bdi_valid = '1' AND bdi_ready = '1' AND word_idx >= TAG_WORDS_C - 1) THEN
                    n_state <= WAIT_ACK;
                END IF;

            WHEN WAIT_ACK =>
                -- Wait until message authentication is acknowledged.
                IF (msg_auth_valid = '1' AND msg_auth_ready = '1') THEN
                    n_state <= IDLE;
                END IF;

            WHEN OTHERS =>
                n_state <= IDLE;

        END CASE;
    END PROCESS p_next_state;

    ----------------------------------------------------------------------------
    --! Decoder process for control logic
    ----------------------------------------------------------------------------
    p_decoder : PROCESS (state, key_valid, key_update, update_key, eot,
        bdi_s, bdi_valid, bdi_ready, bdi_eoi, bdi_eot,
        bdi_size, bdi_type, eoi, hash_in, hash, empty_hash, decrypt_in, decrypt,
        bdo_ready, msg_auth, msg_auth_valid, bdoo_s)
    BEGIN

        -- Default values preventing latches
        key_ready <= '0';
        bdi_ready <= '0';
        msg_auth_valid <= '0';
        n_msg_auth <= msg_auth;
        n_eoi <= eoi;
        n_eot <= eot;
        n_update_key <= update_key;
        n_hash <= hash;
        n_empty_hash <= empty_hash;
        n_decrypt <= decrypt;

        CASE state IS

            WHEN IDLE =>
                -- Default values.
                n_msg_auth <= '1';
                n_eoi <= '0';
                n_eot <= '0';
                n_update_key <= '0';
                n_hash <= '0';
                n_empty_hash <= '0';
                n_decrypt <= '0';
                IF (key_valid = '1' AND key_update = '1') THEN
                    n_update_key <= '1';
                END IF;
                IF (bdi_valid = '1' AND hash_in = '1') THEN
                    n_hash <= '1';
                    IF (bdi_size = EMPTY_HASH_SIZE_C) THEN
                        n_empty_hash <= '1';
                        n_eoi <= '1';
                        n_eot <= '1';
                    END IF;
                END IF;

            WHEN STORE_KEY =>
                -- If key must be updated, assert key_ready.
                IF (update_key = '1') THEN
                    key_ready <= '1';
                END IF;

            WHEN STORE_NONCE =>
                -- Store bdi_eoi (will only be effective on last word) and decrypt_in flag.
                bdi_ready <= '1';
                n_eoi <= bdi_eoi;
                n_decrypt <= decrypt_in;

                -- If pt or ct is detected, don't assert bdi_ready, otherwise first word gets lost.
                -- Remember if eoi and eot were raised during a valid transfer. 
            WHEN ABSORB_AD =>
                IF (bdi_valid = '1' AND bdi_type = HDR_AD) THEN
                    bdi_ready <= '1';
                    n_eoi <= bdi_eoi;
                    n_eot <= bdi_eot;
                END IF;

            WHEN ABSORB_MSG =>
                -- Only signal bdi_ready if bdo can receive data.
                -- Remember if eoi or eot were raised during a valid transfer.
                IF (bdi_valid = '1' AND (bdi_type = HDR_PT OR bdi_type = HDR_CT)) THEN
                    bdi_ready <= bdo_ready;
                    IF (bdi_ready = '1') THEN
                        n_eoi <= bdi_eoi;
                        n_eot <= bdi_eot;
                    END IF;
                END IF;

            WHEN VERIFY_TAG =>
                -- As soon as bdi input doesn't match with calculated tag, reset msg_auth.
                bdi_ready <= '1';
                IF (bdi_valid = '1' AND bdi_ready = '1' AND bdi_type = HDR_TAG) THEN
                    IF (combine_shares(bdi_s) /= combine_shares(bdoo_s)) THEN
                        n_msg_auth <= '0';
                    END IF;
                END IF;

            WHEN WAIT_ACK =>
                -- Signal msg auth valid.
                msg_auth_valid <= '1';

            WHEN OTHERS =>
                NULL;

        END CASE;
    END PROCESS p_decoder;

    ----------------------------------------------------------------------------
    --! Word counters
    ----------------------------------------------------------------------------
    p_counters : PROCESS (clk)
    BEGIN
        IF rising_edge(clk) THEN
            IF (rst = '1') THEN
                word_idx <= 0;
            ELSE
                CASE state IS

                    WHEN IDLE =>
                        -- Nothing to do here, reset counters
                        word_idx <= 0;

                    WHEN STORE_KEY =>
                        -- If key is to be updated, increase counter on every successful
                        -- data transfer (valid and ready), else just count the cycles.
                        IF (key_update = '1') THEN
                            IF (key_valid = '1' AND key_ready = '1') THEN
                                IF (word_idx >= KEY_WORDS_C - 1) THEN
                                    word_idx <= 0;
                                ELSE
                                    word_idx <= word_idx + 1;
                                END IF;
                            END IF;
                        ELSE
                            IF (word_idx >= KEY_WORDS_C - 1) THEN
                                word_idx <= 0;
                            ELSE
                                word_idx <= word_idx + 1; -- todo necessary?
                            END IF;
                        END IF;

                    WHEN STORE_NONCE =>
                        -- Every time a nonce word is transferred, increase counter
                        IF (bdi_valid = '1' AND bdi_ready = '1') THEN
                            IF (word_idx >= NPUB_WORDS_C - 1) THEN
                                word_idx <= 0;
                            ELSE
                                word_idx <= word_idx + 1;
                            END IF;
                        END IF;

                    WHEN ABSORB_AD =>
                        -- On valid transfer, increase word counter until either
                        -- the block size is reached or the last ad word is obtained.
                        IF (bdi_valid = '1' AND bdi_ready = '1') THEN
                            IF (word_idx >= BLOCK_WORDS_C - 1 OR (bdi_eot = '1' AND bdi_partial = '1')) THEN
                                word_idx <= 0;
                            ELSE
                                word_idx <= word_idx + 1;
                            END IF;
                        END IF;

                    WHEN PAD_AD =>
                        word_idx <= 0;

                    WHEN DOM_SEP =>
                        word_idx <= 0;

                    WHEN ABSORB_MSG =>
                        -- On valid transfer, increase word counter until either
                        -- the block size is reached or the last msg word is obtained.
                        IF (bdi_valid = '1' AND bdi_ready = '1') THEN
                            IF (word_idx >= BLOCK_WORDS_C - 1 OR (bdi_eot = '1' AND bdi_partial = '1')) THEN
                                word_idx <= 0;
                            ELSE
                                word_idx <= word_idx + 1;
                            END IF;
                        END IF;

                    WHEN PAD_MSG =>
                        word_idx <= 0;

                    WHEN FINAL_PROCESS | FINAL_KEY_ADD_2 =>
                        word_idx <= 0;

                    WHEN EXTRACT_TAG =>
                        -- Increase word counter on valid bdo transfer until tag size is reached.
                        IF (bdo_valid = '1' AND bdo_ready = '1') THEN
                            IF (word_idx >= TAG_WORDS_C - 1) THEN
                                word_idx <= 0;
                            ELSE
                                word_idx <= word_idx + 1;
                            END IF;
                        END IF;

                    WHEN VERIFY_TAG =>
                        -- Increase word counter when transferring the tag.
                        IF (bdi_valid = '1' AND bdi_ready = '1' AND bdi_type = HDR_TAG) THEN
                            IF (n_state = WAIT_ACK) THEN
                                word_idx <= 0;
                            ELSE
                                word_idx <= word_idx + 1;
                            END IF;
                        END IF;

                    WHEN OTHERS =>
                        NULL;

                END CASE;
            END IF;
        END IF;
    END PROCESS p_counters;

    ----------------------------------------------------------------------------
    --! Ascon FSM
    ----------------------------------------------------------------------------
    p_ascon_fsm : PROCESS (clk)
        VARIABLE rdi_temp : STD_LOGIC_VECTOR(CCW - 1 DOWNTO 0);
    BEGIN
        IF rising_edge(clk) THEN
            IF (rst = '1') THEN
                NULL;
            ELSE
                CASE state IS

                    WHEN IDLE =>
                        NULL;

                    WHEN STORE_KEY =>
                        -- Update key register.
                        IF (key_update = '1') THEN
                            IF (key_valid = '1' AND key_ready = '1') THEN
                                FOR i IN 0 TO D LOOP
                                    ascon_key_s(i)(CCW * word_idx + CCW - 1 DOWNTO CCW * word_idx) <= key_s(i * CCW + CCW - 1 DOWNTO i * CCW);
                                END LOOP;
                            END IF;
                        END IF;

                    WHEN STORE_NONCE =>
                        -- Update nonce register.
                        IF (bdi_valid = '1' AND bdi_ready = '1') THEN
                            FOR i IN 0 TO D LOOP
                                ascon_state(i)(IV_SIZE + KEY_SIZE + CCW * word_idx + CCW - 1 DOWNTO IV_SIZE + KEY_SIZE + CCW * word_idx) <= bdi_s(i * CCW + CCW - 1 DOWNTO i * CCW);
                            END LOOP;
                        END IF;

                    WHEN INIT_STATE_SETUP =>
                        -- Setup state with IV||K||N.
                        FOR share IN 0 TO D LOOP
                            ascon_state(share)(IV_SIZE + KEY_SIZE - 1 DOWNTO IV_SIZE) <= ascon_key_s(share);
                            IF share = D THEN
                                ascon_state(share)(IV_SIZE - 1 DOWNTO 0) <= reverse_byte(IV_AEAD);
                            ELSE
                                ascon_state(share)(IV_SIZE - 1 DOWNTO 0) <= (OTHERS => '0');
                            END IF;
                        END LOOP;
                        ascon_cnt_s <= ROUNDS_A;
                        pad_added <= '0';

                    WHEN INIT_PROCESS =>
                        -- Perform ROUNDS_A permutation rounds.
                        IF (ascon_cnt_s(0) = '1') THEN
                            ascon_state <= asconp_out_s;
                        ELSE
                            ascon_state <= ascon_state;
                        END IF;
                        ascon_cnt_s <= STD_LOGIC_VECTOR(unsigned(ascon_cnt_s) - to_unsigned(UROL, ascon_cnt_s'length));

                    WHEN INIT_KEY_ADD =>
                        -- Perform the key addition after initialization.
                        ascon_cnt_s <= ROUNDS_B;
                        FOR share IN 0 TO D LOOP
                            ascon_state(share)(stateIZE - 1 DOWNTO stateIZE - KEY_SIZE) <= ascon_state(share)(stateIZE - 1 DOWNTO stateIZE - KEY_SIZE) XOR ascon_key_s(share)(KEY_SIZE - 1 DOWNTO 0);
                        END LOOP;

                    WHEN ABSORB_AD =>
                        -- Absorb ad blocks for aead.
                        IF (bdi_valid = '1' AND bdi_ready = '1') THEN
                            -- Absorb ad into the state.
                            ascon_state <= ascon_state_n_s; -- todo new
                            IF (bdi_eot = '1') THEN
                                -- Last absorbed ad block.
                                ascon_cnt_s <= ROUNDS_B;
                                IF (bdi_partial = '1') THEN
                                    pad_added <= '1';
                                ELSIF (word_idx < BLOCK_WORDS_C - 1) THEN
                                    pad_added <= '1';
                                END IF;
                            END IF;
                            IF (word_idx >= BLOCK_WORDS_C - 1) THEN
                                ascon_cnt_s <= ROUNDS_B;
                            END IF;
                        END IF;

                    WHEN PROCESS_AD =>
                        -- Perform ROUNDS_A permutation rounds.
                        IF (ascon_cnt_s(0) = '1') THEN
                            ascon_state <= asconp_out_s;
                        ELSE
                            ascon_state <= ascon_state;
                        END IF;
                        ascon_cnt_s <= STD_LOGIC_VECTOR(unsigned(ascon_cnt_s) - to_unsigned(UROL, ascon_cnt_s'length));

                    WHEN PAD_AD =>
                        -- Absorb empty block with padding.
                        -- (state is only reached if not yet inserted).
                        ascon_state(0)(7 DOWNTO 0) <= ascon_state(0)(7 DOWNTO 0) XOR X"80";
                        pad_added <= '1';
                        ascon_cnt_s <= ROUNDS_B;

                    WHEN DOM_SEP =>
                        -- Perform domain separation.
                        ascon_state(0)(stateIZE - 8) <= ascon_state(0)(stateIZE - 8) XOR '1';
                        pad_added <= '0';

                    WHEN ABSORB_MSG =>
                        -- Absorb msg blocks for aead.
                        IF (bdi_valid = '1' AND bdi_ready = '1') THEN
                            ascon_state <= ascon_state_n_s;
                            IF (bdi_eot = '1') THEN
                                -- Last absorbed msg block.
                                ascon_cnt_s <= ROUNDS_B;
                                IF (bdi_partial = '1') THEN
                                    pad_added <= '1';
                                ELSIF (word_idx < BLOCK_WORDS_C - 1) THEN
                                    pad_added <= '1';
                                END IF;
                            ELSIF (word_idx >= BLOCK_WORDS_C - 1) THEN
                                ascon_cnt_s <= ROUNDS_B;
                            END IF;
                        END IF;

                    WHEN PROCESS_MSG =>
                        -- Perform ROUNDS_A permutation rounds.
                        IF (ascon_cnt_s(0) = '1') THEN
                            ascon_state <= asconp_out_s;
                        ELSE
                            ascon_state <= ascon_state;
                        END IF;
                        ascon_cnt_s <= STD_LOGIC_VECTOR(unsigned(ascon_cnt_s) - to_unsigned(UROL, ascon_cnt_s'length));

                    WHEN PAD_MSG =>
                        -- Absorb empty block with padding.
                        -- (state is only reached if not yet inserted).
                        ascon_state(0)(7 DOWNTO 0) <= ascon_state(0)(7 DOWNTO 0) XOR X"80";
                        pad_added <= '1';

                    WHEN FINAL_KEY_ADD_1 =>
                        -- Second to last key addition.
                        FOR share IN 0 TO D LOOP
                            ascon_state(share)(KEY_SIZE + DBLK_SIZE - 1 DOWNTO DBLK_SIZE) <= ascon_state(share)(KEY_SIZE + DBLK_SIZE - 1 DOWNTO DBLK_SIZE) XOR ascon_key_s(share);
                        END LOOP;
                        ascon_cnt_s <= ROUNDS_A;

                    WHEN FINAL_PROCESS =>
                        -- Perform ROUNDS_A permutation rounds.
                        IF (ascon_cnt_s(0) = '1') THEN
                            ascon_state <= asconp_out_s;
                        ELSE
                            ascon_state <= ascon_state;
                        END IF;
                        ascon_cnt_s <= STD_LOGIC_VECTOR(unsigned(ascon_cnt_s) - to_unsigned(UROL, ascon_cnt_s'length));

                    WHEN FINAL_KEY_ADD_2 =>
                        -- Last key addition.
                        FOR share IN 0 TO D LOOP
                            ascon_state(share)(stateIZE - 1 DOWNTO stateIZE - KEY_SIZE) <= ascon_state(share)(stateIZE - 1 DOWNTO stateIZE - KEY_SIZE) XOR ascon_key_s(share)(KEY_SIZE - 1 DOWNTO 0);
                        END LOOP;

                    WHEN OTHERS =>
                        NULL;

                END CASE;
            END IF;
        END IF;
    END PROCESS p_ascon_fsm;

END behavioral;