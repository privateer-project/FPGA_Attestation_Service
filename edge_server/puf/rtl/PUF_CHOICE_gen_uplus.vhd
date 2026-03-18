--------------------------------------------------------------------------------
-- Title       : PUF "CHOICE" - MULTIPLE INSTANTIATIONS
--------------------------------------------------------------------------------
-- File        : PUF_CHOICE_gen_uplus.vhd
-- Author      : Ilias Papalamprou <ipapalambrou@microlab.ntua.gr>
-- Company     : National Technical University of Athens - Microlab
-- Created     : Mon Nov 18 16:39:57 2024
-- Last update : Tue Nov 19 17:25:43 2024
-- Platform    : AMD (Xilinx) ZCU104 Ultrascale+
-- Standard    : VHDL-2002
--------------------------------------------------------------------------------
-- Copyright (c) 2024 NTUA/Microlab
-------------------------------------------------------------------------------
-- Description: 
-- Modification of the original source file "CHOICE_PUF_gen.vhd" from paper: 
-- "Choice – A Tunable PUF-Design for FPGAs", FLP 2021.
-- Modification is done to support the Ultrascale/Ultrascale+ FPGAs. 
-- The original implementation was based on Series 7 
-- architecture targeting a Zybo-7000 board.
--------------------------------------------------------------------------------
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity puf_choice_gen_uplus is
  ----------------------------------------------------------------------------
  -- COMPONENTS --------------------------------------------------------------
  generic(
    PUF_WIDTH : integer := 128
  );
  Port ( 
    clk             : in std_logic;
    ff_reset        : in std_logic;
    chip_enable     : in std_logic;
    ASR_length_conf : in std_logic_vector(19 downto 0);
    ASR_data_conf   : in std_logic_vector(3 downto 0);
    puf_response    : out std_logic_vector((PUF_WIDTH -1) downto 0)
  );
end puf_choice_gen_uplus;

architecture rtl of puf_choice_gen_uplus is
  ------------------------------------------------------------------------------
  -- COMPONENTS ----------------------------------------------------------------
  component CHOICE_puf_single_uplus is
    Port ( 
      clk             : in std_logic;
      chip_enable     : in std_logic;
      ff_reset        : in std_logic;
      ASR_length_conf : in std_logic_vector(19 downto 0);
      ASR_data_conf   : in std_logic_vector(3 downto 0);
      puf_bit         : out std_logic
    );
  end component;

--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
begin
  GEN_PUF: for I in 0 to (PUF_WIDTH-1) generate
      PUF : CHOICE_puf_single_uplus 
      port map (
        clk,
        chip_enable,
        ff_reset,
        ASR_length_conf,
        ASR_data_conf,
        puf_response(I)
      );
  end generate GEN_PUF;

end rtl;