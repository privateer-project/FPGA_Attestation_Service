library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;
use ieee.math_real.all;

package utility_functions_pkg is
  
  --------------------------------------------------------------
  -- ceil(log2(...)) : Used to compute the number of bits based
  --                   on the maximum value a data can take
  function clog2(value : natural) return natural;
  --------------------------------------------------------------

  --------------------------------------------------------------
  -- float to fix-point sQm.n format
  -- sQm.n: m integer bits 
  --        n fractional bits
  --        m+n total bits
  function float2sfixpnt(value : real; m : natural; n : natural) return signed;
  --------------------------------------------------------------

  --------------------------------------------------------------
  -- float to fix-point uQm.n format
  -- uQm.n: m integer bits
  --        n fractional bits
  --        m+n total bits
  function float2ufixpnt(value : real; m : natural; n : natural) return unsigned;
  --------------------------------------------------------------

  --------------------------------------------------------------
  -- bitgrowth(...) : computes the full precision required for
  --                  a series of MAC operations
  function bitgrowth(coeff_num : natural; coeff_width : natural) return natural;
  --------------------------------------------------------------

end package; -- utility_functions_pkg

package body utility_functions_pkg is

  function clog2(value : natural) return natural is
    variable return_value : natural := 0;
  begin
    return_value := integer(ceil(log2(real(value))));
    return return_value;
  end function;

  function float2sfixpnt(value : real; m : natural; n : natural) return signed is
    variable return_value : signed((m+n)-1 downto 0) := (others => '0');
  begin
    return_value := to_signed(integer(value*real(2**n)), m+n);
    return return_value;
  end function;

  function float2ufixpnt(value : real; m : natural; n : natural) return unsigned is
    variable return_value : unsigned((m+n)-1 downto 0) := (others => '0');
  begin
    return_value := to_unsigned(integer(value*real(2**n)), m+n);
    return return_value;
  end function;

  function bitgrowth(coeff_num : natural; coeff_width : natural) return natural is
    variable return_value : natural := 0;
  begin
    return_value := coeff_width + integer(ceil(log2(real(coeff_num))));
    return return_value;
  end function;

end package body;