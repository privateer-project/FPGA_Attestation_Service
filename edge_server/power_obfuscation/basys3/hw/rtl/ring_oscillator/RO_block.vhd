-- Practical Implementations of Remote Power Side-Channel and Fault-Injection Attacks on Multitenant FPGAs
-- Copyright 2023, School of Computer and Communication Sciences, EPFL.
--
-- All rights reserved. Use of this source code is governed by a
-- BSD-style license that can be found in the LICENSE.md file.
--
-- RO block code 
-- This code describes the desired functionality of the ROs and lets the synthesis tool implement it freely.
-- The outputs might need to be marked as virtual to avoid the synthesis tool optimizing away the entire entity.
-- All of the instantiated ROs share the enable signal.

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity RO_block is 
  generic(
    --N: Number of ROs to instantiate, maps to the expected number of outputs
    N       : integer); 
  port(
    --en: enable signal for the block
    --output: output of the ROs
    en      : in std_logic;
    output  : out std_logic
   );
end RO_block;

architecture RO_arch of RO_block is

signal inv : std_logic_vector(N-1 downto 0);

attribute keep : string;
attribute keep of inv : signal is "true"; 

begin

  inv(0) <= not (inv(N-1) and en);

  gen_inverters: for i in 1 to N-1 generate
    inv(i) <= not inv(i-1);
  end generate;

  output <= inv(N-1);

end architecture RO_arch;