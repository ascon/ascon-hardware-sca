--------------------------------------------------------------------------------
--! @file       Round.vhd
--! @brief      Implementation of Ascon-p using domain-oriented masking
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
--     _                                    
--    / \   ___  ___ ___  _ __          _ __  
--   / _ \ / __|/ __/ _ \| '_ \  _____ | '_ \ 
--  / ___ \\__ \ (_| (_) | | | ||_____|| |_) |
-- /_/   \_\___/\___\___/|_| |_|       | .__/ 
--                                     |_|    
--
--------------------------------------------------------------------------------

LIBRARY ieee;
USE ieee.std_logic_1164.ALL;
USE ieee.numeric_std.ALL;
USE ieee.std_logic_misc.ALL;
USE work.NIST_LWAPI_pkg.ALL;
USE work.design_pkg.ALL;

ENTITY Asconp IS
    PORT (
        clk : IN STD_LOGIC;
        rst : IN STD_LOGIC;
        state_in : IN shared_state2_t;
        rcon : IN STD_LOGIC_VECTOR(3 DOWNTO 0);
        rdi : STD_LOGIC_VECTOR(((D * (D + 1))/2) * 320 - 1 DOWNTO 0);
        rdi_valid : IN STD_LOGIC;
        rdi_ready : OUT STD_LOGIC;
        n_state : state_t;
        state_out : OUT shared_state2_t
    );
END;

ARCHITECTURE behavior OF Asconp IS

    TYPE asconp_state_t IS (
        IDLE,
        COMPUTE,
        INTEGRATE
    );
    
    SIGNAL s_affine_1st : shared_state_t(4 DOWNTO 0);
    SIGNAL r_affine_1st : shared_state_t(4 DOWNTO 0);

    SIGNAL x0_dom_calc_out : shared_lane_t((D + 1) * (D + 1) - 1 DOWNTO 0);
    SIGNAL x1_dom_calc_out : shared_lane_t((D + 1) * (D + 1) - 1 DOWNTO 0);
    SIGNAL x2_dom_calc_out : shared_lane_t((D + 1) * (D + 1) - 1 DOWNTO 0);
    SIGNAL x3_dom_calc_out : shared_lane_t((D + 1) * (D + 1) - 1 DOWNTO 0);
    SIGNAL x4_dom_calc_out : shared_lane_t((D + 1) * (D + 1) - 1 DOWNTO 0);

    SIGNAL x0_dom_integrate_in : shared_lane_t((D + 1) * (D + 1) - 1 DOWNTO 0);
    SIGNAL x1_dom_integrate_in : shared_lane_t((D + 1) * (D + 1) - 1 DOWNTO 0);
    SIGNAL x2_dom_integrate_in : shared_lane_t((D + 1) * (D + 1) - 1 DOWNTO 0);
    SIGNAL x3_dom_integrate_in : shared_lane_t((D + 1) * (D + 1) - 1 DOWNTO 0);
    SIGNAL x4_dom_integrate_in : shared_lane_t((D + 1) * (D + 1) - 1 DOWNTO 0);

    SIGNAL asconp_state, nx_asconp_state : asconp_state_t;

    SIGNAL rdi_s : random_shares2_t;

    ----------------------------------------------------------------------------
    --! Combinatorial logic of first affine layer
    ----------------------------------------------------------------------------
    FUNCTION affine_1st(s2 : shared_state2_t; rc : STD_LOGIC_VECTOR(3 DOWNTO 0))
        RETURN shared_state_t IS
        VARIABLE ss : shared_state_t(4 DOWNTO 0);
        VARIABLE rc_temp : STD_LOGIC_VECTOR(3 DOWNTO 0);
        CONSTANT rounds_16 : STD_LOGIC_VECTOR(3 DOWNTO 0) := X"F";
        CONSTANT rounds_12 : STD_LOGIC_VECTOR(3 DOWNTO 0) := X"C";
    BEGIN
        FOR x IN 0 TO 4 LOOP
            FOR share IN 0 TO D LOOP
                ss(x)(share) := s2(share)(63 + x * 64 DOWNTO x * 64);
                ss(x)(share) := reverse_byte(ss(x)(share));
            END LOOP;
        END LOOP;
        FOR share IN 0 TO D LOOP
            rc_temp := STD_LOGIC_VECTOR(unsigned(rounds_12) - unsigned(rc));
            ss(0)(share) := ss(0)(share) XOR ss(4)(share);
            IF share = 0 THEN
                ss(2)(share)(7 DOWNTO 0) := ss(2)(share)(7 DOWNTO 0) XOR ss(1)(share)(7 DOWNTO 0) XOR (STD_LOGIC_VECTOR(unsigned(rounds_16) - unsigned(rc_temp)) & rc_temp);
                ss(2)(share)(63 DOWNTO 8) := ss(2)(share)(63 DOWNTO 8) XOR ss(1)(share)(63 DOWNTO 8);
            ELSE
                ss(2)(share) := ss(2)(share) XOR ss(1)(share);
            END IF;
            ss(4)(share) := ss(4)(share) XOR ss(3)(share);
        END LOOP;
        RETURN ss;
    END FUNCTION affine_1st;

    ----------------------------------------------------------------------------
    --! Negation of shared lane
    ----------------------------------------------------------------------------
    FUNCTION negate_lane(x : shared_lane_t(D DOWNTO 0))
        RETURN shared_lane_t IS
        VARIABLE y : shared_lane_t(D DOWNTO 0) := x;
    BEGIN
        y(0) := NOT y(0);
        RETURN y;
    END FUNCTION negate_lane;

    ----------------------------------------------------------------------------
    --! Combinatorial logic of DOM calculation phase
    ----------------------------------------------------------------------------
    FUNCTION DOM_calculation(X : shared_lane_t(D DOWNTO 0); Y : shared_lane_t(D DOWNTO 0); Z : shared_lane_t(((D * (D + 1))/2) - 1 DOWNTO 0))
        RETURN shared_lane_t IS
        VARIABLE Xi_mul_Yj : shared_lane_t((D + 1) * (D + 1) - 1 DOWNTO 0);
    BEGIN
        FOR i IN D DOWNTO 0 LOOP
            FOR j IN D DOWNTO 0 LOOP
                IF i = j THEN
                    Xi_mul_Yj((D + 1) * i + j) := X(i) AND Y(j);
                ELSIF j > i THEN
                    Xi_mul_Yj((D + 1) * i + j) := (X(i) AND Y(j)) XOR Z(i + j * (j - 1)/2);
                ELSE
                    Xi_mul_Yj((D + 1) * i + j) := (X(i) AND Y(j)) XOR Z(j + i * (i - 1)/2);
                END IF;
            END LOOP;
        END LOOP;
        RETURN Xi_mul_Yj;
    END FUNCTION DOM_calculation;

    ----------------------------------------------------------------------------
    --! Combinatorial logic of DOM integration phase
    ----------------------------------------------------------------------------
    FUNCTION DOM_integration(Xi_mul_Yj : shared_lane_t((D + 1) * (D + 1) - 1 DOWNTO 0); Xi_mul_Yj_r : shared_lane_t((D + 1) * (D + 1) - 1 DOWNTO 0))
        RETURN shared_lane_t IS
        VARIABLE result : STD_LOGIC_VECTOR(63 DOWNTO 0);
        VARIABLE Q : shared_lane_t(D DOWNTO 0);
    BEGIN
        FOR i IN 0 TO D LOOP
            result := (OTHERS => '0');
            FOR j IN 0 TO D LOOP
                IF i = j THEN
                    result := result XOR Xi_mul_Yj((D + 1) * i + j);
                ELSE
                    result := result XOR Xi_mul_Yj_r((D + 1) * i + j);
                END IF;
            END LOOP;
            Q(i) := result;
        END LOOP;
        RETURN Q;
    END FUNCTION DOM_integration;

BEGIN

    ----------------------------------------------------------------------------
    --! Init/reset logic
    ----------------------------------------------------------------------------
    p_reg : PROCESS (clk)
    BEGIN
        IF rising_edge(clk) THEN
            IF (rst = '1') THEN
                asconp_state <= IDLE;
            ELSE
                asconp_state <= nx_asconp_state;
            END IF;
        END IF;
    END PROCESS p_reg;

    ----------------------------------------------------------------------------
    --! next-state/rdi logic
    ----------------------------------------------------------------------------
    p_next_state : PROCESS (asconp_state, n_state)
    BEGIN

        -- Default values preventing latches
        nx_asconp_state <= asconp_state;
        rdi_ready <= '0';

        CASE asconp_state IS

            WHEN IDLE =>
                IF (n_state = INIT_PROCESS OR n_state = PROCESS_AD OR n_state = PROCESS_MSG OR n_state = FINAL_PROCESS) THEN
                    nx_asconp_state <= COMPUTE;
                END IF;

            WHEN COMPUTE =>
                nx_asconp_state <= INTEGRATE;
                rdi_ready <= '1';

            WHEN INTEGRATE =>
                IF (n_state = INIT_PROCESS OR n_state = PROCESS_AD OR n_state = PROCESS_MSG OR n_state = FINAL_PROCESS) THEN
                    nx_asconp_state <= COMPUTE;
                ELSE
                    nx_asconp_state <= IDLE;
                END IF;

            WHEN OTHERS =>
                nx_asconp_state <= IDLE;

        END CASE;
    END PROCESS p_next_state;
    
    ----------------------------------------------------------------------------
    --! 1st affine layer
    ----------------------------------------------------------------------------
    s_affine_1st <= affine_1st(state_in, rcon);

    ----------------------------------------------------------------------------
    --! Register stage after affine layer (updates on negative clk edge)
    ----------------------------------------------------------------------------
    p_ascon_fsm1 : PROCESS (clk)
    BEGIN

        IF falling_edge(clk) THEN

            CASE asconp_state IS

                WHEN COMPUTE =>
                    -- registers are only needed for certain lanes that can cause glitchy input dependencies in the later DOM-AND
                    r_affine_1st(0) <= s_affine_1st(0);
                    r_affine_1st(2) <= s_affine_1st(2);
                    r_affine_1st(4) <= s_affine_1st(4);

                WHEN OTHERS =>
                    NULL;

            END CASE;

        END IF;

    END PROCESS p_ascon_fsm1;

    ----------------------------------------------------------------------------
    --! Map rdi input to chunks of 64-bit as required in the DOM-AND
    ----------------------------------------------------------------------------
    rdi_gen : FOR share IN 0 TO ((D * (D + 1))/2) - 1 GENERATE
    
        rdi_gen2 : FOR i IN 0 TO 4 GENERATE
        
            rdi_s(i)(share) <= rdi(320 * share + 64 * i + 64 - 1 DOWNTO 320 * share + 64 * i);
            
        END GENERATE rdi_gen2;
        
    END GENERATE rdi_gen;

    ----------------------------------------------------------------------------
    --! Calculation phase of DOM-AND
    --! Uses registered signals if glitch-related input dependencies could occur in the DOM-And
    --! Otherwise uses signals directly
    ----------------------------------------------------------------------------
    x0_dom_calc_out <= DOM_calculation(negate_lane(s_affine_1st(1)), r_affine_1st(2), rdi_s(0));
    x1_dom_calc_out <= DOM_calculation(negate_lane(r_affine_1st(2)), s_affine_1st(3), rdi_s(1));
    x2_dom_calc_out <= DOM_calculation(negate_lane(s_affine_1st(3)), r_affine_1st(4), rdi_s(2));
    x3_dom_calc_out <= DOM_calculation(negate_lane(r_affine_1st(4)), r_affine_1st(0), rdi_s(3));
    x4_dom_calc_out <= DOM_calculation(negate_lane(r_affine_1st(0)), s_affine_1st(1), rdi_s(4));
    
    ----------------------------------------------------------------------------
    --! Register stage between calculation and integration phase of DOM-AND
    ----------------------------------------------------------------------------
    p_ascon_fsm2 : PROCESS (clk)
    BEGIN

        IF rising_edge(clk) THEN

            CASE asconp_state IS

                WHEN COMPUTE =>

                    -- integrate_in holds the dom_calc_out signals in registers.
                    -- Only some of these registers are later used in DOM_integration.
                    -- Otherwise signals are used directely and unused registers should get optimized away.
                    x0_dom_integrate_in <= x0_dom_calc_out;
                    x1_dom_integrate_in <= x1_dom_calc_out;
                    x2_dom_integrate_in <= x2_dom_calc_out;
                    x3_dom_integrate_in <= x3_dom_calc_out;
                    x4_dom_integrate_in <= x4_dom_calc_out;

                WHEN OTHERS =>
                    NULL;

            END CASE;

        END IF;

    END PROCESS p_ascon_fsm2;

    ----------------------------------------------------------------------------
    --! Integration phase of DOM-AND + 2nd affine layer
    ----------------------------------------------------------------------------
    PROCESS (x0_dom_integrate_in, x1_dom_integrate_in, x2_dom_integrate_in, x3_dom_integrate_in, x4_dom_integrate_in)
        VARIABLE x0, x1, x2, x3, x4 : shared_lane_t(D DOWNTO 0);
    BEGIN

        x0 := DOM_integration(x0_dom_calc_out, x0_dom_integrate_in);
        x1 := DOM_integration(x1_dom_calc_out, x1_dom_integrate_in);
        x2 := DOM_integration(x2_dom_calc_out, x2_dom_integrate_in);
        x3 := DOM_integration(x3_dom_calc_out, x3_dom_integrate_in);
        x4 := DOM_integration(x4_dom_calc_out, x4_dom_integrate_in);

        FOR share IN 0 TO D LOOP

            -- affine layer has an incomplete register layer
            x0(share) := r_affine_1st(0)(share) XOR x0(share);
            x1(share) := s_affine_1st(1)(share) XOR x1(share);
            x2(share) := r_affine_1st(2)(share) XOR x2(share);
            x3(share) := s_affine_1st(3)(share) XOR x3(share);
            x4(share) := r_affine_1st(4)(share) XOR x4(share);

            x1(share) := x1(share) XOR x0(share);
            x3(share) := x3(share) XOR x2(share);
            x0(share) := x0(share) XOR x4(share);
            IF share = 0 THEN
                x2(share) := NOT x2(share);
            END IF;
            
            x0(share) := x0(share) XOR (x0(share)(18 DOWNTO 0) & x0(share)(63 DOWNTO 19)) XOR (x0(share)(27 DOWNTO 0) & x0(share)(63 DOWNTO 28));
            x1(share) := x1(share) XOR (x1(share)(60 DOWNTO 0) & x1(share)(63 DOWNTO 61)) XOR (x1(share)(38 DOWNTO 0) & x1(share)(63 DOWNTO 39));
            x2(share) := x2(share) XOR (x2(share)(0 DOWNTO 0) & x2(share)(63 DOWNTO 1)) XOR (x2(share)(5 DOWNTO 0) & x2(share)(63 DOWNTO 6));
            x3(share) := x3(share) XOR (x3(share)(9 DOWNTO 0) & x3(share)(63 DOWNTO 10)) XOR (x3(share)(16 DOWNTO 0) & x3(share)(63 DOWNTO 17));
            x4(share) := x4(share) XOR (x4(share)(6 DOWNTO 0) & x4(share)(63 DOWNTO 7)) XOR (x4(share)(40 DOWNTO 0) & x4(share)(63 DOWNTO 41));
            
            state_out(share)(63 + 0 * 64 DOWNTO 0 * 64) <= reverse_byte(x0(share));
            state_out(share)(63 + 1 * 64 DOWNTO 1 * 64) <= reverse_byte(x1(share));
            state_out(share)(63 + 2 * 64 DOWNTO 2 * 64) <= reverse_byte(x2(share));
            state_out(share)(63 + 3 * 64 DOWNTO 3 * 64) <= reverse_byte(x3(share));
            state_out(share)(63 + 4 * 64 DOWNTO 4 * 64) <= reverse_byte(x4(share));
        END LOOP;

    END PROCESS;

END;
