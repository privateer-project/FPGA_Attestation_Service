--------------------------------------------------------------------------------
-- Title       : PUF "CHOICE" - AXI4-LITE INTERFACE
-- Project     : Default Project Name
--------------------------------------------------------------------------------
-- File        : axi4lite_puf.vhd
-- Author      : Ilias Papalamprou <ipapalambrou@microlab.ntua.com>
-- Company     : National Technical University of Athens (NTUA) - Microlab
-- Created     : Tue Nov 19 17:26:12 2024
-- Last update : Tue Nov 26 19:57:56 2024
-- Platform    : AMD (Xilinx) ZCU104 Ultrascale+
-- Standard    : VHDL-2002
--------------------------------------------------------------------------------
-- Copyright (c) 2024 NTUA/Microlab
-------------------------------------------------------------------------------
-- Description: 
-- Main AXI4-Lite interface for PUF
--------------------------------------------------------------------------------
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.utility_functions_pkg.all;

entity axi4lite is
  generic (
    ----------------------------------------------------------------------------
    -- AXI4-LITE PARAMETERS ----------------------------------------------------
    C_AXI_ADDR_WIDTH    : natural   := 4;
    C_AXI_DATA_WIDTH    : natural   := 32;
    C_S_AXIS_DATA_WIDTH : natural   := 32;
    C_M_AXIS_DATA_WIDTH : natural   := 32;
    OPT_SKIDBUFFER      : std_logic := '1';
    ----------------------------------------------------------------------------
    -- PUF PARAMETERS ----------------------------------------------------------
    PUF_WIDTH           : natural   := 128
  );

  port (
    ----------------------------------------------------------------------------
    -- AXI4-LITE INTERFACE -----------------------------------------------------
    -- COMMON
    S_AXI_ACLK    : in  std_logic;
    S_AXI_ARESETN : in  std_logic;
    -- AW CHANNEL
    S_AXI_AWADDR  : in  std_logic_vector(C_AXI_ADDR_WIDTH-1 downto 0);
    S_AXI_AWVALID : in  std_logic;
    S_AXI_AWREADY : out std_logic;
    S_AXI_AWPROT  : in  std_logic_vector(3-1 downto 0);
    -- W CHANNEL
    S_AXI_WDATA   : in  std_logic_vector(C_AXI_DATA_WIDTH-1 downto 0);
    S_AXI_WVALID  : in  std_logic;
    S_AXI_WREADY  : out std_logic;
    S_AXI_WSTRB   : in  std_logic_vector((C_AXI_DATA_WIDTH/8)-1 downto 0);
    -- B CHANNEL
    S_AXI_BRESP   : out std_logic_vector(2-1 downto 0);
    S_AXI_BVALID  : out std_logic;
    S_AXI_BREADY  : in  std_logic;
    -- AR CHANNEL (address read)
    S_AXI_ARADDR  : in  std_logic_vector(C_AXI_ADDR_WIDTH-1 downto 0);
    S_AXI_ARVALID : in  std_logic;
    S_AXI_ARREADY : out std_logic;
    S_AXI_ARPROT  : in  std_logic_vector(3-1 downto 0);
    -- R CHANNEL
    S_AXI_RDATA   : out std_logic_vector(C_AXI_DATA_WIDTH-1 downto 0);
    S_AXI_RRESP   : out std_logic_vector(2-1 downto 0);
    S_AXI_RVALID  : out std_logic;
    S_AXI_RREADY  : in  std_logic
   );
end entity;

architecture arch of axi4lite is

  constant ADDR_LSB : natural := clog2(C_AXI_DATA_WIDTH)-3; -- clog2(C_AXI_DATA_WIDTH)-3;

  -- PUF_WIDTH/C_AXI_DATA_WIDTH registers for writing PUF response
  -- (PUF_WIDTH/C_AXI_DATA_WIDTH)/2 registers for reading PUF configuration
  -- One extra register reserved for valid/ready flags
  --constant REGISTER_NUM  : natural := (3/2)*(PUF_WIDTH/C_AXI_DATA_WIDTH) + 1;
  constant REGISTER_NUM  : natural := 7;

  signal slvl_awaddr  : std_logic_vector(C_AXI_ADDR_WIDTH-1 downto 0);
  signal slvl_awvalid : std_logic;
  signal slvl_awready : std_logic;
  signal slvl_awprot  : std_logic_vector(3-1 downto 0);

  signal slvl_wdata  : std_logic_vector(C_AXI_DATA_WIDTH-1 downto 0);
  signal slvl_wvalid : std_logic;
  signal slvl_wready : std_logic;
  signal slvl_wstrb  : std_logic_vector((C_AXI_DATA_WIDTH/8)-1 downto 0);
  
  signal slvl_bresp  : std_logic_vector(2-1 downto 0);
  signal slvl_bvalid : std_logic;
  signal slvl_bready : std_logic;

  signal slvl_araddr  : std_logic_vector(C_AXI_ADDR_WIDTH-1 downto 0);
  signal slvl_arvalid : std_logic;
  signal slvl_arready : std_logic;
  signal slvl_arprot  : std_logic_vector(3-1 downto 0);

  signal slvl_rdata  : std_logic_vector(C_AXI_DATA_WIDTH-1 downto 0);
  signal slvl_rresp  : std_logic_vector(2-1 downto 0);
  signal slvl_rvalid : std_logic;
  signal slvl_rready : std_logic;

  signal slvs_tdata  : std_logic_vector(C_S_AXIS_DATA_WIDTH-1 downto 0);
  signal slvs_tvalid : std_logic;
  signal slvs_tready : std_logic;
  signal slvs_tlast  : std_logic;

  signal msts_tdata  : std_logic_vector(C_M_AXIS_DATA_WIDTH-1 downto 0);
  signal msts_tvalid : std_logic;
  signal msts_tready : std_logic;
  signal msts_tlast  : std_logic;

  ------------------------------------------------------------------------------
  -- COMPONENTS ----------------------------------------------------------------
  component skidbuffer is
    generic (
      OPT_OUTREG      : std_logic := '1';
      OPT_PASSTHROUGH : std_logic := '0';
      DATA_WIDTH      : natural := 8
    );
    port (
      aclk       : in  std_logic;
      arst       : in  std_logic;
      slv_tdata  : in  std_logic_vector(DATA_WIDTH-1 downto 0);
      slv_tready : out std_logic;
      slv_tvalid : in  std_logic;
      mst_tdata  : out std_logic_vector(DATA_WIDTH-1 downto 0);
      mst_tready : in  std_logic;
      mst_tvalid : out std_logic
    );     
  end component;


  component puf_choice_gen_uplus is
    generic (
      PUF_WIDTH : integer := 128
    );
    port (
      clk             : in  std_logic;
      ff_reset        : in  std_logic;
      chip_enable     : in  std_logic;
      ASR_length_conf : in  std_logic_vector(19 downto 0);
      ASR_data_conf   : in  std_logic_vector(3 downto 0);
      puf_response    : out std_logic_vector((PUF_WIDTH -1) downto 0)
    );
  end component puf_choice_gen_uplus;  


  component PUF_controller is
    port (
      clk         : in  STD_LOGIC;
      payload     : in  STD_LOGIC_VECTOR(63 downto 0);
      read_valid  : in  STD_LOGIC;
      write_ready : in  STD_LOGIC;
      read_ready  : out STD_LOGIC;
      write_valid : out STD_LOGIC;
      ff_reset    : out STD_LOGIC;
      ASR_enable  : out STD_LOGIC;
      ASR_tuning  : out STD_LOGIC_VECTOR(19 downto 0);
      ASR_choice  : out STD_LOGIC_VECTOR(3 downto 0)
    );
  end component PUF_controller;  

  ------------------------------------------------------------------------------
  ------------------------------------------------------------------------------
  -- DEBUGING ------------------------------------------------------------------
  
  component ila_puf is
    port (
      clk    : in std_logic;
      probe0 : in std_logic_vector(63 downto 0);
      probe1 : in std_logic;
      probe2 : in std_logic;
      probe3 : in std_logic_vector(3 downto 0);
      probe4 : in std_logic;
      probe5 : in std_logic_vector(19 downto 0);
      probe6 : in std_logic_vector(127 downto 0)
    );
  end component ila_puf;

  --   ila_puf your_instance_name (
  -- 	.clk(clk), // input wire clk


  -- 	.probe0(probe0), // input wire [63:0]  probe0  
  -- 	.probe1(probe1), // input wire [0:0]  probe1 
  -- 	.probe2(probe2), // input wire [0:0]  probe2 
  -- 	.probe3(probe3), // input wire [3:0]  probe3 
  -- 	.probe4(probe4), // input wire [0:0]  probe4 
  -- 	.probe5(probe5), // input wire [19:0]  probe5 
  -- 	.probe6(probe6) // input wire [127:0]  probe6
  -- );

  ------------------------------------------------------------------------------
  ------------------------------------------------------------------------------
  signal puf_response         : std_logic_vector(PUF_WIDTH-1 downto 0);

  signal puf_reset            : std_logic;

  signal puf_ctrl_payload     : std_logic_vector(64-1 downto 0);
  signal puf_ctrl_payload_reg : std_logic_vector(64-1 downto 0);

  signal puf_ctrl_rd_valid    : std_logic;
  signal puf_ctrl_wr_ready    : std_logic;
  signal puf_ctrl_rd_ready    : std_logic;
  signal puf_ctrl_wr_valid    : std_logic;
  signal puf_ctrl_asr_enable  : std_logic;
  signal puf_ctrl_asr_tuning  : std_logic_vector(20-1 downto 0);
  signal puf_ctrl_asr_choice  : std_logic_vector(4-1 downto 0);

  attribute MARK_DEBUG : string;
  attribute MARK_DEBUG of puf_ctrl_payload    : signal is "true";
  attribute MARK_DEBUG of puf_ctrl_asr_choice : signal is "true";
  attribute MARK_DEBUG of puf_ctrl_asr_enable : signal is "true";
  attribute MARK_DEBUG of puf_ctrl_asr_tuning : signal is "true";
  attribute MARK_DEBUG of puf_response        : signal is "true";
  attribute MARK_DEBUG of puf_ctrl_wr_ready   : signal is "true";
  attribute MARK_DEBUG of puf_ctrl_rd_valid   : signal is "true";

  ------------------------------------------------------------------------------
  ------------------------------------------------------------------------------

  constant COUNT_MAX_VALUE    : natural := 64;
  constant COUNT_WIDTH        : natural := clog2(COUNT_MAX_VALUE); -- 6
  signal symbol_counter       : unsigned(COUNT_WIDTH-1 downto 0) := (others => '0');
  signal symbol_counter_limit : unsigned(COUNT_WIDTH-1 downto 0);

  signal slv_ifft_cfg_tdata_reg  : std_logic_vector(16-1 downto 0) := (others => '0');
  signal slv_ifft_cfg_tvalid_reg : std_logic := '0';
  signal slv_ifft_cfg_tready     : std_logic;

  signal skid_0to1_dat_tdata  : std_logic_vector(32-1 downto 0);
  signal skid_0to1_dat_tvalid : std_logic;
  signal skid_0to1_dat_tready : std_logic;
  signal skid_0to1_dat_tlast  : std_logic;

  signal slv_ifft_dat_tdata     : std_logic_vector(32-1 downto 0);
  signal slv_ifft_dat_tvalid    : std_logic;
  signal slv_ifft_dat_tready    : std_logic;
  signal slv_ifft_dat_tlast_reg : std_logic := '0';
  signal slv_ifft_dat_tlast     : std_logic;

  signal mst_ifft_dat_tdata      : std_logic_vector(C_M_AXIS_DATA_WIDTH-1 downto 0);
  alias  mst_ifft_dat_tdata_real : std_logic_vector((C_M_AXIS_DATA_WIDTH/2)-1 downto 0) is mst_ifft_dat_tdata((C_M_AXIS_DATA_WIDTH/2)-1 downto                      0 );
  alias  mst_ifft_dat_tdata_imag : std_logic_vector((C_M_AXIS_DATA_WIDTH/2)-1 downto 0) is mst_ifft_dat_tdata( C_M_AXIS_DATA_WIDTH   -1 downto (C_M_AXIS_DATA_WIDTH/2));
  signal mst_ifft_dat_tvalid     : std_logic;
  signal mst_ifft_dat_tready     : std_logic;
  signal mst_ifft_dat_tlast      : std_logic;

  signal areset : std_logic;

  signal axil_write_ready : std_logic;

  signal awskd_addr : std_logic_vector(C_AXI_ADDR_WIDTH-ADDR_LSB-1 downto 0);

  signal wskd_data : std_logic_vector(32-1 downto 0);
  signal wskd_strb : std_logic_vector((32/8)-1 downto 0);

  signal axil_bvalid : std_logic := '0';

  signal axil_read_ready : std_logic;

  signal arskd_addr : std_logic_vector(C_AXI_ADDR_WIDTH-ADDR_LSB-1 downto 0);

  signal axil_read_data : std_logic_vector(32-1 downto 0) := (others => '0');

  signal axil_read_valid : std_logic := '0';

  --type slv_reg_t is array (0 to REGISTER_NUM-1) of std_logic_vector(32-1 downto 0);
  type slv_reg_t is array (0 to 3-1) of std_logic_vector(32-1 downto 0);
  signal puf_input_reg_file : slv_reg_t := (others => (others => '0'));

  ------------------------------------------------------------------------------
  ------------------------------------------------------------------------------
  -- FSM for correcting control unit input control signals
  type fsm_type is (init_state, first_pulse, second_pulse);
  signal fsm_state : fsm_type;

  type fsm_type_2 is (init_state, pulse);
  signal fsm_pulse : fsm_type_2;

  ------------------------------------------------------------------------------
  ------------------------------------------------------------------------------
  type reg_file_t is array (0 to 4-1) of std_logic_vector(32-1 downto 0);
  signal puf_response_reg_file : reg_file_t := (others => (others => '0'));

  --------------------------------------------------------
  --------------------------------------------------------
  --------------------------------------------- TIME SHIFT
  signal toggle_selector      : std_logic := '0';
  signal time_shift_tdata     : std_logic_vector(C_M_AXIS_DATA_WIDTH-1 downto 0);
  alias time_shift_tdata_real : std_logic_vector((C_M_AXIS_DATA_WIDTH/2)-1 downto 0) is time_shift_tdata((C_M_AXIS_DATA_WIDTH/2)-1 downto                      0 );
  alias time_shift_tdata_imag : std_logic_vector((C_M_AXIS_DATA_WIDTH/2)-1 downto 0) is time_shift_tdata( C_M_AXIS_DATA_WIDTH   -1 downto (C_M_AXIS_DATA_WIDTH/2));

begin

  areset        <= not S_AXI_ARESETN;

  -- AW CH
  slvl_awaddr   <= S_AXI_AWADDR;
  slvl_awvalid  <= S_AXI_AWVALID;
  S_AXI_AWREADY <= slvl_awready;
  slvl_awprot   <= S_AXI_AWPROT;
  -- W CH
  slvl_wdata    <= S_AXI_WDATA;
  slvl_wvalid   <= S_AXI_WVALID;
  S_AXI_WREADY  <= slvl_wready;
  slvl_wstrb    <= S_AXI_WSTRB;
  -- B CH
  S_AXI_BRESP   <= slvl_bresp;
  S_AXI_BVALID  <= slvl_bvalid;
  slvl_bready   <= S_AXI_BREADY;
  -- AR CH
  slvl_araddr   <= S_AXI_ARADDR;
  slvl_arvalid  <= S_AXI_ARVALID;
  S_AXI_ARREADY <= slvl_arready;
  slvl_arprot   <= S_AXI_ARPROT;
  -- R CH
  S_AXI_RDATA   <= slvl_rdata;
  S_AXI_RRESP   <= slvl_rresp;
  S_AXI_RVALID  <= slvl_rvalid;
  slvl_rready   <= S_AXI_RREADY;


  GEN_SKIDBUFFER_WRITE : if (OPT_SKIDBUFFER = '1') generate
    signal awskd_valid : std_logic;
    signal wskd_valid  : std_logic;
  begin

    AW_CHANNEL_SKIDBUFFER : skidbuffer
      generic map (
                   OPT_OUTREG      => '1',
                   OPT_PASSTHROUGH => '0',
                   DATA_WIDTH      => C_AXI_ADDR_WIDTH - ADDR_LSB
                  )
      port map (
                aclk       => S_AXI_ACLK,
                arst       => areset,
                slv_tdata  => slvl_awaddr(C_AXI_ADDR_WIDTH-1 downto ADDR_LSB),
                slv_tready => slvl_awready,
                slv_tvalid => slvl_awvalid,
                mst_tdata  => awskd_addr,
                mst_tready => axil_write_ready,
                mst_tvalid => awskd_valid
               );

    W_CHANNEL_SKIDBUFFER : skidbuffer
      generic map (
                   OPT_OUTREG      => '1',
                   OPT_PASSTHROUGH => '0',
                   DATA_WIDTH      => 32 + (32/8)
                  )
      port map (
                aclk       => S_AXI_ACLK,
                arst       => areset,
                slv_tdata((32 + (32/8))-1 downto (32/8)) => slvl_wdata,
                slv_tdata((      32/8) -1 downto      0) => slvl_wstrb,
                slv_tready => slvl_wready,
                slv_tvalid => slvl_wvalid,
                mst_tdata((32 + (32/8))-1 downto (32/8)) => wskd_data,
                mst_tdata((      32/8) -1 downto      0) => wskd_strb,
                mst_tready => axil_write_ready,
                mst_tvalid => wskd_valid
               );

    axil_write_ready <= awskd_valid and wskd_valid and ((not slvl_bvalid) or slvl_bready);

  end generate;

  GEN_SIMPLE_WRITES : if (OPT_SKIDBUFFER = '0') generate
    signal axil_awready : std_logic := '0';
  begin

    WRITE_LOGIC: process(S_AXI_ACLK)
    begin
      if (rising_edge(S_AXI_ACLK)) then
        if (areset = '1') then
          axil_awready <= '0';
        else
          axil_awready <= (not axil_awready)
                          and (slvl_awvalid and slvl_wvalid)
                          and ((not slvl_bvalid) and slvl_bready);
        end if;
      end if;
    end process;

    slvl_awready <= axil_awready;
    slvl_wready  <= axil_awready;

    awskd_addr <= slvl_awaddr(C_AXI_ADDR_WIDTH-1 downto ADDR_LSB);
    wskd_data  <= slvl_wdata;
    wskd_strb  <= slvl_wstrb;

    axil_write_ready <= axil_awready;

  end generate;

  WRITE_RESPONSE : process(S_AXI_ACLK)
  begin
    if (rising_edge(S_AXI_ACLK)) then
      if (areset = '1') then
        axil_bvalid <= '0';
      else
        if (axil_write_ready = '1') then
          axil_bvalid <= '1';
        elsif (slvl_bready = '1') then
          axil_bvalid <= '0';
        else
          axil_bvalid <= axil_bvalid;
        end if;
      end if;
    end if;
  end process;

  slvl_bvalid <= axil_bvalid;
  slvl_bresp  <= "00";

  GEN_SKIDBUFFER_READ : if (OPT_SKIDBUFFER = '1') generate
    signal arskd_valid : std_logic;
  begin

    AR_CHANNEL_SKIDBUFFER : skidbuffer
      generic map (
                   OPT_OUTREG      => '1',
                   OPT_PASSTHROUGH => '0',
                   DATA_WIDTH      => C_AXI_ADDR_WIDTH - ADDR_LSB
                  )
      port map (
                aclk       => S_AXI_ACLK,
                arst       => areset,
                slv_tdata  => slvl_araddr(C_AXI_ADDR_WIDTH-1 downto ADDR_LSB),
                slv_tready => slvl_arready,
                slv_tvalid => slvl_arvalid,
                mst_tdata  => arskd_addr,
                mst_tready => axil_read_ready,
                mst_tvalid => arskd_valid
               );

    axil_read_ready <= arskd_valid and ((not axil_read_valid) or slvl_rready);

  end generate;

  GEN_SIMPLE_READ : if (OPT_SKIDBUFFER = '0') generate
    signal axil_arready : std_logic;
  begin

    axil_arready    <= not slvl_rvalid;
    arskd_addr      <= slvl_araddr(C_AXI_ADDR_WIDTH-1 downto ADDR_LSB);
    slvl_arready     <= axil_arready;
    axil_read_ready <= slvl_arvalid and slvl_arready;

  end generate;

  READ_RESPONSE : process(S_AXI_ACLK)
  begin
    if (rising_edge(S_AXI_ACLK)) then
      if (areset = '1') then
        axil_read_valid <= '0';
      else
        if (axil_read_ready = '1') then
          axil_read_valid <= '1';
        elsif (slvl_rready = '1') then
          axil_read_valid <= '0';
        else
          axil_read_valid <= axil_read_valid;
        end if;
      end if;
    end if;
  end process;

  slvl_rvalid <= axil_read_valid;
  slvl_rdata  <= axil_read_data;
  slvl_rresp  <= "00";

  WRITE_REGISTERS : process(S_AXI_ACLK)
    variable localWrAddr : natural := 0;
  begin
    if (rising_edge(S_AXI_ACLK)) then
      if (areset = '1') then
        puf_input_reg_file <= (others => (others => '0'));
      else
        if (axil_write_ready = '1') then
          puf_input_reg_file(to_integer(unsigned(awskd_addr))) <= wskd_data;
        else
          puf_input_reg_file <= puf_input_reg_file;
        end if;
      end if;
    end if;
  end process;

  READ_REGISTERS : process(S_AXI_ACLK)
  begin
    if (rising_edge(S_AXI_ACLK)) then
      if (areset = '1') then
        axil_read_data <= (others => '0');
      else
        if ((slvl_rvalid = '0') or (slvl_rready = '1')) then
          --axil_read_data <= puf_input_reg_file(to_integer(unsigned(arskd_addr)));
          axil_read_data <= puf_response_reg_file(to_integer(unsigned(arskd_addr)));
        else
          axil_read_data <= axil_read_data;
        end if;
      end if;
    end if;
  end process;


  ------------------------------------------------------------------------------
  ------------------------------------------------------------------------------
  -- PUF COMPONENT ------------------------------------------------------------- 

  --READ_PUF_PAYLOAD : process(S_AXI_ACLK)
  --begin
  --  if (rising_edge(S_AXI_ACLK)) then
  --    if (areset = '1') then
  --      puf_ctrl_payload <= (others => '0');
  --    else
  --      puf_ctrl_payload <= puf_input_reg_file(2) & puf_input_reg_file(1);
  --    end if;
  --  end if;
  --end process;

  --puf_ctrl_payload  <= puf_input_reg_file(2) & puf_input_reg_file(1);
  --puf_ctrl_rd_valid <= puf_input_reg_file(0)(0);
  --puf_ctrl_wr_ready <= puf_input_reg_file(0)(1);

  -- puf_ctrl_payload  <= puf_input_reg_file(1) & puf_input_reg_file(0);
  puf_ctrl_payload_reg  <= puf_input_reg_file(1) & puf_input_reg_file(0);

  -- PUF controller read valid signal
  -- puf_ctrl_rd_valid <= (axil_write_ready and puf_input_reg_file(2)(0));



  -- puf_ctrl_rd_valid <= axil_write_ready; -- This should be replaced ....

  -- Logic to make puf_ctrl_rd_valid signal '1' after both registers are written
  RD_VALID_GEN : process(S_AXI_ACLK)
  begin
    if (rising_edge(S_AXI_ACLK)) then
      if (areset = '1') then 
        puf_ctrl_rd_valid <= '0';
        fsm_state <= init_state;
      else
        case fsm_state is
          when init_state =>
            puf_ctrl_rd_valid <= '0';
            if (axil_write_ready = '1') then
              puf_ctrl_rd_valid <= '0';
              fsm_state <= first_pulse;
            end if;
          when first_pulse =>
            if (axil_write_ready = '1') then
              puf_ctrl_rd_valid <= '0';
              fsm_state <= second_pulse;
            end if;
          when second_pulse =>
            puf_ctrl_rd_valid <= '1';
            fsm_state <= init_state;
        end case;
      end if;
    end if;
  end process;

  
  -- puf_ctrl_wr_ready <= axil_read_ready;  -- This needs improving...

  WR_READY_LOGIC : process(S_AXI_ACLK)
  begin
    if (rising_edge(S_AXI_ACLK)) then
      if (areset = '1') then
        puf_ctrl_wr_ready <= '0';
        fsm_pulse <= init_state;
      else
        case fsm_pulse is 
          when init_state =>
            puf_ctrl_wr_ready <= '0';
            if (axil_read_ready = '1') then
              puf_ctrl_wr_ready <= '1';
              fsm_pulse <= pulse;
            end if;
          when pulse =>
            puf_ctrl_wr_ready <= '0';
            if (puf_ctrl_rd_valid = '1') then
              fsm_pulse <= init_state;
            end if;
        end case;
      end if;
    end if;
  end process;



  PAYLOAD_REG : process(S_AXI_ACLK)
  begin
    if (rising_edge(S_AXI_ACLK)) then
      if (areset = '1') then
        puf_ctrl_payload <= (others => '0');
      else
        puf_ctrl_payload <= puf_ctrl_payload_reg;
      end if;
    end if;
  end process;


  PUF_CTRL_UNIT : PUF_controller
    port map (
      clk             => S_AXI_ACLK,
      payload         => puf_ctrl_payload,
      read_valid      => puf_ctrl_rd_valid,   -- alternative: constant '1'
      -- read_valid      => '1',      
      write_ready     => puf_ctrl_wr_ready,   -- alternative: constant '1'
      -- write_ready     => '1',
      read_ready      => puf_ctrl_rd_ready,
      write_valid     => puf_ctrl_wr_valid,
      ff_reset        => puf_reset,
      ASR_enable      => puf_ctrl_asr_enable,
      ASR_tuning      => puf_ctrl_asr_tuning,
      ASR_choice      => puf_ctrl_asr_choice
    );  


  PUF_MODULE : puf_choice_gen_uplus
    generic map (
      PUF_WIDTH       => PUF_WIDTH
    )
    port map (
      clk             => S_AXI_ACLK,
      ff_reset        => puf_reset,
      chip_enable     => puf_ctrl_asr_enable,
      ASR_length_conf => puf_ctrl_asr_tuning,
      ASR_data_conf   => puf_ctrl_asr_choice,
      puf_response    => puf_response
    );


    WRITE_PUF_RESPONSE : process(S_AXI_ACLK)
    begin
      if (rising_edge(S_AXI_ACLK)) then
        if (areset = '1') then
          puf_response_reg_file(0) <= (others => '0');
          puf_response_reg_file(1) <= (others => '0');
          puf_response_reg_file(2) <= (others => '0');
          puf_response_reg_file(3) <= (others => '0');
        
        else
          -- if ((puf_ctrl_wr_valid = '1') and (puf_ctrl_wr_ready = '1')) then
          if (puf_ctrl_wr_ready = '1') then
          -- if (puf_ctrl_wr_valid = '1') then
            puf_response_reg_file(0) <= puf_response(31   downto  0);
            puf_response_reg_file(1) <= puf_response(63   downto 32);
            puf_response_reg_file(2) <= puf_response(95   downto 64);
            puf_response_reg_file(3) <= puf_response(127  downto 96);
          else
            puf_response_reg_file(0) <= puf_response_reg_file(0);
            puf_response_reg_file(1) <= puf_response_reg_file(1);
            puf_response_reg_file(2) <= puf_response_reg_file(2);
            puf_response_reg_file(3) <= puf_response_reg_file(3);
          end if;

        end if;
      end if;
    end process;


  ---------------------------------------------------------------------------------
  ---------------------------------------------------------------------------------
  -- ILA FOR DEBUG
  -- DEBUG_ILA : ila_puf
  --   port map (
  --     clk     => S_AXI_ACLK,
  --     probe0  => puf_ctrl_payload,
  --     probe1  => '1',
  --     probe2  => '1',
  --     probe3  => puf_ctrl_asr_choice,
  --     probe4  => puf_ctrl_asr_enable,
  --     probe5  => puf_ctrl_asr_tuning,
  --     probe6  => puf_response
  --   );

---------------------------------------------------------------------------------
---------------------------------------------------------------------------------
---------------------------------------------------------------------------------
---------------------------------------------------------------------------------
---------------------------------------------------------------------------------
  --IFFT_DATA_INPUT_CHANNEL_SKIDBUFFER_STG_0 : skidbuffer
  --  generic map (
  --               OPT_OUTREG      => '1',
  --               OPT_PASSTHROUGH => '0',
  --               DATA_WIDTH      => 32
  --              )
  --  port map (
  --            aclk       => S_AXI_ACLK,
  --            arst       => areset,
  --            slv_tdata  => slvs_tdata,
  --            slv_tready => slvs_tready,
  --            slv_tvalid => slvs_tvalid,
  --            mst_tdata  => skid_0to1_dat_tdata,
  --            mst_tready => skid_0to1_dat_tready,
  --            mst_tvalid => skid_0to1_dat_tvalid
  --           );


  --IFFT_DATA_INPUT_CHANNEL_SKIDBUFFER_STG_1 : skidbuffer
  --  generic map (
  --               OPT_OUTREG      => '1',
  --               OPT_PASSTHROUGH => '0',
  --               DATA_WIDTH      => 32+1
  --              )
  --  port map (
  --            aclk       => S_AXI_ACLK,
  --            arst       => areset,
  --            slv_tdata(32+1-1 downto 1) => skid_0to1_dat_tdata,
  --            slv_tdata(              0) => slv_ifft_dat_tlast_reg,
  --            slv_tready => skid_0to1_dat_tready,
  --            slv_tvalid => skid_0to1_dat_tvalid,
  --            mst_tdata(32+1-1 downto 1)  => slv_ifft_dat_tdata,
  --            mst_tdata(              0)  => slv_ifft_dat_tlast,
  --            mst_tready => slv_ifft_dat_tready,
  --            mst_tvalid => slv_ifft_dat_tvalid
  --           );

  --COUNT_SYMBOLS : process(S_AXI_ACLK)
  --begin
  --  if (rising_edge(S_AXI_ACLK)) then
  --    if (areset = '1') then
  --      symbol_counter <= (others => '0');
  --    else
  --      if ((skid_0to1_dat_tvalid = '1') and (skid_0to1_dat_tready = '1') and (slv_ifft_dat_tlast_reg = '1')) then
  --        symbol_counter <= (others => '0');
  --      elsif ((skid_0to1_dat_tvalid = '1') and (skid_0to1_dat_tready = '1')) then
  --        symbol_counter <= symbol_counter + 1;
  --      else
  --        symbol_counter <= symbol_counter;
  --      end if;
  --    end if;
  --  end if;
  --end process;

  --symbol_counter_limit <= unsigned(puf_input_reg_file(0)(21 downto 17) & '0');
  --GENERATE_TLAST : process(S_AXI_ACLK)
  --begin
  --  if (rising_edge(S_AXI_ACLK)) then
  --    if (areset = '1') then
  --      slv_ifft_dat_tlast_reg <= '0';
  --    else
  --      if ((skid_0to1_dat_tvalid = '1') and (skid_0to1_dat_tready = '1') and (slv_ifft_dat_tlast_reg = '1')) then
  --        slv_ifft_dat_tlast_reg <= '0';
  --      elsif ((skid_0to1_dat_tvalid = '1') and (skid_0to1_dat_tready = '1') and (symbol_counter = symbol_counter_limit)) then
  --        slv_ifft_dat_tlast_reg <= '1';
  --      else
  --        slv_ifft_dat_tlast_reg <= slv_ifft_dat_tlast_reg;
  --      end if;
  --    end if;
  --  end if;
  --end process;

  --GENERATE_IFFT_CFG : process(S_AXI_ACLK)
  --begin
  --  if (rising_edge(S_AXI_ACLK)) then
  --    if (areset = '1') then
  --      slv_ifft_cfg_tdata_reg  <= (others => '0');
  --      slv_ifft_cfg_tvalid_reg <= '0';
  --    else
  --      if ((skid_0to1_dat_tready = '1') and (skid_0to1_dat_tvalid = '1')) then
  --        if (symbol_counter = to_unsigned(0, COUNT_WIDTH)) then
  --          slv_ifft_cfg_tdata_reg  <= puf_input_reg_file(0)(15 downto 0);
  --          slv_ifft_cfg_tvalid_reg <= '1';
  --        else
  --          slv_ifft_cfg_tdata_reg  <= slv_ifft_cfg_tdata_reg;
  --          slv_ifft_cfg_tvalid_reg <= '0';
  --        end if;
  --      else
  --        slv_ifft_cfg_tdata_reg  <= slv_ifft_cfg_tdata_reg;
  --        slv_ifft_cfg_tvalid_reg <= '0';
  --      end if;
  --    end if;
  --  end if;
  --end process;

  --IFFT_CORE : ifft
  --  PORT MAP (
  --            aclk                        => S_AXI_ACLK,
  --            aresetn                     => S_AXI_ARESETN,

  --            s_axis_config_tdata         => slv_ifft_cfg_tdata_reg,
  --            s_axis_config_tvalid        => slv_ifft_cfg_tvalid_reg,
  --            s_axis_config_tready        => slv_ifft_cfg_tready,

  --            s_axis_data_tdata           => slv_ifft_dat_tdata,
  --            s_axis_data_tvalid          => slv_ifft_dat_tvalid,
  --            s_axis_data_tready          => slv_ifft_dat_tready,
  --            s_axis_data_tlast           => slv_ifft_dat_tlast,

  --            m_axis_data_tdata           => mst_ifft_dat_tdata,
  --            m_axis_data_tvalid          => mst_ifft_dat_tvalid,
  --            m_axis_data_tready          => mst_ifft_dat_tready,
  --            m_axis_data_tlast           => mst_ifft_dat_tlast,

  --            event_frame_started         => open,
  --            event_tlast_unexpected      => open,
  --            event_tlast_missing         => open,
  --            event_status_channel_halt   => open,
  --            event_data_in_channel_halt  => open,
  --            event_data_out_channel_halt => open
  --           );

  --msts_tdata  <= mst_ifft_dat_tdata;
  --msts_tvalid <= mst_ifft_dat_tvalid;
  --mst_ifft_dat_tready <= msts_tready;
  --msts_tlast <= mst_ifft_dat_tlast;

end architecture; 