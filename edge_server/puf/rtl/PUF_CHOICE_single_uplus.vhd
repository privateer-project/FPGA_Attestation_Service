--------------------------------------------------------------------------------
-- Title       : PUF "CHOICE" - SINGLE CELL
--------------------------------------------------------------------------------
-- File        : PUF_CHOICE_single_uplus.vhd
-- Author      : Ilias Papalamprou <ipapalambrou@microlab.ntua.gr>
-- Company     : National Technical University of Athens - Microlab
-- Created     : Mon Nov 18 16:37:18 2024
-- Last update : Mon Nov 18 18:12:00 2024
-- Platform    : AMD (Xilinx) ZCU104 Ultrascale+
-- Standard    : VHDL-2002
--------------------------------------------------------------------------------
-- Copyright (c) 2024 Microlab
-------------------------------------------------------------------------------
-- Description: 
-- Modification of the original source file "CHOICE_PUF_single.vhd" from paper: 
-- "Choice – A Tunable PUF-Design for FPGAs", FLP 2021.
-- Modification is done to support the Ultrascale/Ultrascale+ FPGAs. 
-- The original implementation was based on Series 7 
-- architecture targeting a Zybo-7000 board.
--------------------------------------------------------------------------------
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;
library unisim;
use unisim.vcomponents.all;

entity CHOICE_puf_single_uplus is
    port (
        clk                  : in std_logic;
        chip_enable          : in std_logic;
        ff_reset             : in std_logic;
        ASR_length_conf      : in std_logic_vector(19 downto 0);
        ASR_data_conf        : in std_logic_vector(3 downto 0);
        puf_bit              : out std_logic
    );
end CHOICE_puf_single_uplus;

architecture Behavioral of CHOICE_puf_single_uplus is

    -- PUF signals
    signal carry_out        : std_logic;
    -- signal carry_dummy      : std_logic_vector(2 downto 0);
    -- signal carry_dummy      : std_logic_vector(7-1 downto 0);

    signal carry_dummy_3bit : std_logic_vector(3-1 downto 0);
    signal carry_dummy_4bit : std_logic_vector(4-1 downto 0);

    signal ASRQ0            : std_logic;
    signal ASRQ1            : std_logic;
    signal ASRQ2            : std_logic;
    signal ASRQ3            : std_logic;

    -- Attributes
    attribute DONT_TOUCH    : string;
    attribute DONT_TOUCH of CARRY8_inst : label is "TRUE";
    -- attribute DONT_TOUCH of  CARRY4_inst : label is "TRUE";

begin

    SRLC32E_inst_3 : SRLC32E
    generic map (
        INIT => X"00000000"
    )
    port map (
        Q   => ASRQ3,                           -- SRL data output
        Q31 => open,                            -- SRL cascade output pin
        A   => ASR_length_conf(19 downto 15),   -- 5-bit shift length select input
        CE  => chip_enable,                     -- Chip enable input
        CLK => clk,                             -- Clock input
        D   => ASR_data_conf(3)                 -- SRL data input
    );

    SRLC32E_inst_2 : SRLC32E
    generic map (
        INIT => X"00000000"
    )
    port map (
        Q   => ASRQ2,                           -- SRL data output
        Q31 => open,                            -- SRL cascade output pin
        A   => ASR_length_conf(14 downto 10),   -- 5-bit shift length select input
        CE  => chip_enable,                     -- Chip enable input
        CLK => clk,                             -- Clock input
        D   => ASR_data_conf(2)                 -- SRL data input
    );

    SRLC32E_inst_1 : SRLC32E
    generic map (
        INIT => X"00000000"
    )
    port map (
        Q   => ASRQ1,                           -- SRL data output
        Q31 => open,                            -- SRL cascade output pin
        A   => ASR_length_conf(9 downto 5),     -- 5-bit shift length select input
        CE  => chip_enable,                     -- Chip enable input
        CLK => clk,                             -- Clock input
        D   => ASR_data_conf(1)                 -- SRL data input
    );

    SRLC32E_inst_0 : SRLC32E
    generic map (
        INIT => X"00000000"
    )
    port map (
        Q   => ASRQ0,                           -- SRL data output
        Q31 => open,                            -- SRL cascade output pin
        A   => ASR_length_conf(4 downto 0),     -- 5-bit shift length select input
        CE  => chip_enable,                     -- Chip enable input
        CLK => clk,                             -- Clock input
        D   => ASR_data_conf(0)                 -- SRL data input
    );

    -- ipapal modification : Use CARRY8 instead of CARRY4

    -- CARRY4_inst : CARRY4                        -- the "top" carry chain
    -- port map (
    --     CO(3)          => carry_out,
    --     CO(2 downto 0) => carry_dummy,
    --     O              => open,                 -- 4-bit carry chain XOR data out
    --     CI             => '1',                  -- 1-bit carry cascade input (prev CARRY_BW)
    --     CYINIT         => '1',                  -- 1-bit carry initialization (prev 0)
    --     DI             => "0000",               -- 4-bit carry-MUX data in
    --     S(3)           => ASRQ3,
    --     S(2)           => ASRQ2,
    --     S(1)           => ASRQ1,
    --     S(0)           => ASRQ0
    -- );



    -- CARRY8_inst : CARRY8
    -- generic map (
    --     CARRY_TYPE => "SINGLE_CY8"  -- 8-bit or dual 4-bit carry (DUAL_CY4, SINGLE_CY8)
    -- )
    -- port map (
    --     CO(3)          => carry_out,
    --     CO(2 downto 0) => carry_dummy,
    --     CO(7 downto 4) => open,
    --     O              => open,                 -- 4-bit carry chain XOR data out
    --     CI             => '1',                  -- 1-bit carry cascade input (prev CARRY_BW)
    --     DI             => "00000000",           -- 8-bit carry-MUX data in
    --     S(3)           => ASRQ3,
    --     S(2)           => ASRQ2,
    --     S(1)           => ASRQ1,
    --     S(0)           => ASRQ0,
    --     S(7 downto 4)  => open
    -- );


    -- CARRY8_inst : CARRY8
    -- generic map (
    --     CARRY_TYPE => "DUAL_CY4"
    -- )
    -- port map (
    --     CO(7)          => carry_out,
    --     CO(6 downto 0) => carry_dummy,
    --     O              => open,                 -- 4-bit carry chain XOR data out
    --     CI             => '1',                  -- 1-bit carry cascade input (prev CARRY_BW)
    --     DI             => "00000000",           -- 8-bit carry-MUX data in
    --     S(7)           => ASRQ3,
    --     S(6)           => ASRQ2,
    --     S(5)           => ASRQ1,
    --     S(4)           => ASRQ0,
    --     S(3 downto 0)  => open
    -- );


    CARRY8_inst : CARRY8
    generic map (
        CARRY_TYPE => "DUAL_CY4"
    )
    port map (
        CO(7 downto 4) => carry_dummy_4bit,
        CO(3)          => carry_out,
        CO(2 downto 0) => carry_dummy_3bit,
        O              => open,                 -- 4-bit carry chain XOR data out
        CI             => '1',                  -- 1-bit carry cascade input (prev CARRY_BW)
        DI             => "00000000",           -- 8-bit carry-MUX data in
        S(3)           => ASRQ3,
        S(2)           => ASRQ2,
        S(1)           => ASRQ1,
        S(0)           => ASRQ0,
        S(7 downto 4)  => open
    );


    FDCPE_inst : FDPE
    generic map (
        INIT => '0'
    ) 
    port map (
        Q   => puf_bit,                         -- Data output
        C   => clk,                             -- Clock input
        CE  => ff_reset,                        -- Clock enable input
        D   => '0',                             -- Data input
        PRE => carry_out                        -- Asynchronous set input
    );


end Behavioral;
