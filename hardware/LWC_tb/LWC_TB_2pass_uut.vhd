library ieee;
use ieee.std_logic_1164.all;

use work.NIST_LWAPI_pkg.all;
use work.LWC_compatibility_pkg.all;

entity LWC_TB_2pass_uut is
    generic (
          G_MAX_SEGMENT_BYTES : integer := 4 * 1024
    );
    port (
        clk             : in  std_logic;
        rst             : in  std_logic;
        pdi_data        : in  std_logic_vector(W-1 downto 0);
        pdi_valid       : in  std_logic;
        pdi_ready       : out std_logic;
        sdi_data        : in  std_logic_vector(SW-1 downto 0);
        sdi_valid       : in  std_logic;
        sdi_ready       : out std_logic;
        do_data         : out std_logic_vector(W-1 downto 0);
        do_ready        : in  std_logic;
        do_valid        : out std_logic;
        do_last         : out std_logic
    );
end entity;

architecture structural of LWC_TB_2pass_uut is

    --! fdi/o
    signal fdi_data             : std_logic_vector(W-1 downto 0);
    signal fdo_data             : std_logic_vector(W-1 downto 0);
    signal fdi_valid            : std_logic;
    signal fdo_valid            : std_logic;
    signal fdi_ready            : std_logic;
    signal fdo_ready            : std_logic;

    component LWC_2pass
        port (
            clk       : in  std_logic;
            rst       : in  std_logic;
            pdi_data  : in  std_logic_vector(W - 1 downto 0);
            pdi_valid : in  std_logic;
            pdi_ready : out std_logic;
            sdi_data  : in  std_logic_vector(SW - 1 downto 0);
            sdi_valid : in  std_logic;
            sdi_ready : out std_logic;
            do_data   : out std_logic_vector(W - 1 downto 0);
            do_ready  : in  std_logic;
            do_valid  : out std_logic;
            do_last   : out std_logic;
            fdi_data  : in  std_logic_vector(W - 1 downto 0);
            fdi_valid : in  std_logic;
            fdi_ready : out std_logic;
            fdo_data  : out std_logic_vector(W - 1 downto 0);
            fdo_valid : out std_logic;
            fdo_ready : in  std_logic
        );
    end component;
begin

    assert False report "Using LWC_2pass with G_MAX_SEGMENT_BYTES=" & integer'image(G_MAX_SEGMENT_BYTES) severity warning;
    
    uut: LWC_2pass
        port map(
            clk          => clk,
            rst          => rst,
            pdi_data     => pdi_data,
            pdi_valid    => pdi_valid,
            pdi_ready    => pdi_ready,
            sdi_data     => sdi_data,
            sdi_valid    => sdi_valid,
            sdi_ready    => sdi_ready,
            do_data      => do_data,
            do_ready     => do_ready,
            do_valid     => do_valid,
            do_last      => do_last,
            fdi_data     => fdi_data,
            fdi_valid    => fdi_valid,
            fdi_ready    => fdi_ready,
            fdo_data     => fdo_data,
            fdo_valid    => fdo_valid,
            fdo_ready    => fdo_ready
        );

    twoPassfifo : entity work.FIFO
        generic map(
            G_W              => W,
            G_DEPTH          => G_MAX_SEGMENT_BYTES / (W/8)
        )
        port map(
            clk              => clk,
            rst              => rst,
            din              => fdo_data,
            din_valid        => fdo_valid,
            din_ready        => fdo_ready,
            dout             => fdi_data,
            dout_valid       => fdi_valid,
            dout_ready       => fdi_ready
        );  
end architecture;
