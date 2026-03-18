library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity skidbuffer is
  generic (
           OPT_OUTREG      : std_logic := '1';
           OPT_PASSTHROUGH : std_logic := '0';
           DATA_WIDTH      : natural   := 8
          );
  port (
        aclk       : in std_logic;
        arst       : in std_logic; -- active high
        -- SLAVE IF
        slv_tdata  : in  std_logic_vector(DATA_WIDTH-1 downto 0); -- i_data
        slv_tready : out std_logic; -- o_ready
        slv_tvalid : in  std_logic; -- i_valid
        -- MASTER IF
        mst_tdata  : out std_logic_vector(DATA_WIDTH-1 downto 0); -- o_data
        mst_tready : in  std_logic; -- i_ready
        mst_tvalid : out std_logic  -- o_valid
       );
end entity; -- skidbuffer

architecture arch of skidbuffer is

  constant OPT_LOWPOWER : std_logic := '0';

  signal i_data  : std_logic_vector(DATA_WIDTH-1 downto 0);
  signal i_valid : std_logic;
  signal o_ready : std_logic;

  signal o_data  : std_logic_vector(DATA_WIDTH-1 downto 0);
  signal o_valid : std_logic;
  signal i_ready : std_logic;

  signal w_data : std_logic_vector(DATA_WIDTH-1 downto 0);

begin

  i_data     <= slv_tdata;
  i_valid    <= slv_tvalid;
  slv_tready <= o_ready;

  mst_tdata  <= o_data;
  mst_tvalid <= o_valid;
  i_ready    <= mst_tready;

  GEN_PASSTHROUGH : if (OPT_PASSTHROUGH = '1') generate -- GEN_PASSTHROUGH START

    o_valid <= i_valid;
    o_ready <= i_ready;

    mst_tdata <= (others => '0') when ((i_valid = '0') and (OPT_LOWPOWER = '1')) else
                 i_data;


    w_data <= (others => '0');
  end generate; -- GEN_PASSTHROUGH END


  GEN_NORMAL : if (OPT_PASSTHROUGH = '0') generate -- GEN_NORMAL START

    signal r_valid : std_logic := '0';
    signal r_data  : std_logic_vector(DATA_WIDTH-1 downto 0) := (others => '0');

  begin

    R_VALID_LOGIC : process(aclk)
    begin
      if (rising_edge(aclk)) then
        if (arst = '1') then
          r_valid <= '0';
        else
          if (((i_valid = '1') and (o_ready = '1')) and ((o_valid = '1') and (i_ready = '0')) )then
            r_valid <= '1';
          elsif (i_ready = '1') then
            r_valid <= '0';
          else
            r_valid <= r_valid;
          end if;
        end if;
      end if;
    end process;

    R_DATA_LOGIC : process(aclk)
    begin
      if (rising_edge(aclk)) then
        if (arst = '1') then
          r_data <= (others => '0');
        else
          if ((OPT_LOWPOWER = '1') and ( (o_valid = '0') or (i_ready = '1')  )) then
            r_data <= (others => '0');
          elsif ( ((OPT_LOWPOWER = '0') or (OPT_OUTREG = '0') or (i_valid = '1')) and (o_ready = '1') ) then
            r_data <= i_data;
          else
            r_data <= r_data;
          end if;
        end if;
      end if;
    end process;

    w_data <= r_data;

    o_ready <= not r_valid;

    GEN_OUTREG_N : if (OPT_OUTREG = '0') generate -- GEN_OUTREG_N START
      o_valid <= (not arst) and (i_valid or r_valid);

      o_data <= r_data    when (r_valid = '1') else
                i_data when ((OPT_LOWPOWER = '0') or (i_valid = '1')) else
                (others => '0');
    end generate; -- GEN_OUTREG_N END

    GEN_OUTREG_Y : if (OPT_OUTREG = '1') generate -- GEN_OUTREG_N START
      signal ro_valid : std_logic := '0';
    begin

      MST_TVALID_LOGIC : process(aclk)
      begin
        if (rising_edge(aclk)) then 
          if (arst = '1') then
            ro_valid <= '0';
          else
            if ( (o_valid = '0') or (i_ready = '1') ) then
              ro_valid <= i_valid or r_valid;
            else
              ro_valid <= ro_valid;
            end if;
          end if;
        end if;
      end process;

      o_valid <= ro_valid;

      MST_TDATA_LOGIC : process(aclk)
      begin
        if (rising_edge(aclk)) then 
          if (arst = '1') then
            o_data <= (others => '0');
          else
            if ( (o_valid = '0') or (i_ready = '1') ) then
              if (r_valid = '1') then
                o_data <= r_data;
              elsif ( (OPT_LOWPOWER = '0') or (i_valid = '1') ) then
                o_data <= i_data;
              else
                o_data <= o_data;
              end if;
            else
              o_data <= o_data;
            end if;
          end if;
        end if;
      end process;
    end generate; -- GEN_OUTREG_N END

  end generate;  -- GEN_NORMAL END

end architecture; -- arch