library ieee;
use ieee.std_logic_1164.all;

use work.NIST_LWAPI_pkg.all;

entity LWC_2pass_wrapper is
    port(
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
end LWC_2pass_wrapper;

architecture RTL of LWC_2pass_wrapper is
    signal lwc_pdi_data  : std_logic_vector(W - 1 downto 0);
    signal lwc_pdi_valid : std_logic;
    signal lwc_pdi_ready : std_logic;
    signal lwc_sdi_data  : std_logic_vector(SW - 1 downto 0);
    signal lwc_sdi_valid : std_logic;
    signal lwc_sdi_ready : std_logic;
    signal lwc_do_data   : std_logic_vector(W - 1 downto 0);
    signal lwc_do_ready  : std_logic;
    signal lwc_do_valid  : std_logic;
    signal lwc_do_last   : std_logic;
    signal lwc_fdi_data  : std_logic_vector(W - 1 downto 0);
    signal lwc_fdi_valid : std_logic;
    signal lwc_fdi_ready : std_logic;
    signal lwc_fdo_data  : std_logic_vector(W - 1 downto 0);
    signal lwc_fdo_valid : std_logic;
    signal lwc_fdo_ready : std_logic;

    signal do_datalast_i : std_logic_vector(W downto 0);
    signal do_datalast_o : std_logic_vector(W downto 0);

    component LWC_2pass
        port(
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
    end component LWC_2pass;

begin

    assert False report "Using LWC_2pass_wrapper" severity warning;

    LWC_inst : LWC_2pass
        port map(
            clk       => clk,
            rst       => rst,
            pdi_data  => lwc_pdi_data,
            pdi_valid => lwc_pdi_valid,
            pdi_ready => lwc_pdi_ready,
            sdi_data  => lwc_sdi_data,
            sdi_valid => lwc_sdi_valid,
            sdi_ready => lwc_sdi_ready,
            do_data   => lwc_do_data,
            do_ready  => lwc_do_ready,
            do_valid  => lwc_do_valid,
            do_last   => lwc_do_last,
            fdi_data  => lwc_fdi_data,
            fdi_valid => lwc_fdi_valid,
            fdi_ready => lwc_fdi_ready,
            fdo_data  => lwc_fdo_data,
            fdo_valid => lwc_fdo_valid,
            fdo_ready => lwc_fdo_ready
        );

    elastic_reg_fifo_pdi : entity work.FIFO
        generic map(
            G_W         => W,
            G_DEPTH     => 2,
            G_ELASTIC_2 => True
        )
        port map(
            clk        => clk,
            rst        => rst,
            din        => pdi_data,
            din_valid  => pdi_valid,
            din_ready  => pdi_ready,
            dout       => lwc_pdi_data,
            dout_valid => lwc_pdi_valid,
            dout_ready => lwc_pdi_ready
        );

    elastic_reg_fifo_sdi : entity work.FIFO
        generic map(
            G_W         => SW,
            G_DEPTH     => 2,
            G_ELASTIC_2 => True
        )
        port map(
            clk        => clk,
            rst        => rst,
            din        => sdi_data,
            din_valid  => sdi_valid,
            din_ready  => sdi_ready,
            dout       => lwc_sdi_data,
            dout_valid => lwc_sdi_valid,
            dout_ready => lwc_sdi_ready
        );

    elastic_reg_fifo_do : entity work.FIFO
        generic map(
            G_W         => W + 1,
            G_DEPTH     => 2,
            G_ELASTIC_2 => True
        )
        port map(
            clk        => clk,
            rst        => rst,
            din        => do_datalast_i,
            din_valid  => lwc_do_valid,
            din_ready  => lwc_do_ready,
            dout       => do_datalast_o,
            dout_valid => do_valid,
            dout_ready => do_ready
        );

    elastic_reg_fifo_fdi : entity work.FIFO
        generic map(
            G_W         => W,
            G_DEPTH     => 2,
            G_ELASTIC_2 => True
        )
        port map(
            clk        => clk,
            rst        => rst,
            din        => fdi_data,
            din_valid  => fdi_valid,
            din_ready  => fdi_ready,
            dout       => lwc_fdi_data,
            dout_valid => lwc_fdi_valid,
            dout_ready => lwc_fdi_ready
        );

    elastic_reg_fifo_fdo : entity work.FIFO
        generic map(
            G_W         => W,
            G_DEPTH     => 2,
            G_ELASTIC_2 => True
        )
        port map(
            clk        => clk,
            rst        => rst,
            din        => lwc_fdo_data,
            din_valid  => lwc_fdo_valid,
            din_ready  => lwc_fdo_ready,
            dout       => fdo_data,
            dout_valid => fdo_valid,
            dout_ready => fdo_ready
        );

    do_datalast_i <= lwc_do_last & lwc_do_data;
    do_last       <= do_datalast_o(W);
    do_data       <= do_datalast_o(W - 1 downto 0);

end architecture;
