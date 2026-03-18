library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity RO_array is
  generic (
    -- NUM_ROS: number of ring oscillators to instantiate
    NUM_ROS : integer
  );
  port (
    -- en: shared enable signal
    en      : in  std_logic;
    -- output: vector of individual RO outputs
    output  : out std_logic_vector(NUM_ROS-1 downto 0)
  );
end RO_array;

architecture Structural of RO_array is


  component RO_block
    generic (
      N : integer  -- number of inverters per RO
    );
    port (
      en     : in  std_logic;
      output : out std_logic
    );
  end component;

begin

  -- Generate multiple independent 5-stage ring oscillators
  gen_ros: for i in 0 to NUM_ROS-1 generate
    ro_bl: RO_block
      generic map (
        N => 5  
      )
      port map (
        en     => en,
        output => output(i)
      );
  end generate;

end architecture Structural;
