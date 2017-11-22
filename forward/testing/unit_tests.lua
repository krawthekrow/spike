local ffi = require("ffi")

local B = require("apps.basic.basic_apps")
local P = require("apps.pcap.pcap")
local IPV4 = require("lib.protocol.ipv4")
local IPV6 = require("lib.protocol.ipv6")
local Datagram = require("lib.protocol.datagram")

local Rewriting = require("rewriting")
local godefs = require("godefs")

local PacketSynthesisContext = require("testing/packet_synthesis")
local TestStreamApp = require("testing/test_stream_app")
local TestCollectApp = require("testing/test_collect_app")
local MockGoInterface = require("testing/mock_go_interface")

local UnitTests = {}

function UnitTests:new(network_config)
   return setmetatable({
      network_config = network_config,
      synthesis = PacketSynthesisContext:new(network_config, false),
      in_stream_app = nil,
      expected_stream_app = nil,
      out_collect_app = nil,
      expected_collect_app = nil
   }, {
      __index = UnitTests
   })
end

-- Arguments:
-- test_name (string) -- Name of test.
-- input_packets (array of packets) -- Packets to stream into Spike.
-- expected_output_packets (array of packets) -- Packets to compare
--    Spike's output with.
function UnitTests:run_test(test_name, input_packets, expected_output_packets)
   print("Running test: "..test_name)
   self.in_stream_app:init(input_packets)
   self.expected_stream_app:init(expected_output_packets)

   local expected_num_output_packets = #expected_output_packets

   local err = nil
   local test_start_time = os.clock()
   local flush_counter = -1
   engine.main({done = function()
      if os.clock() - test_start_time > 0.1 then
         err = "Test timed out. Possibly too many packets were dropped."
         return true
      end

      if flush_counter ~= -1 then
         if #self.out_collect_app.packets ~=
            expected_num_output_packets then
            err = "Too may packets produced."
            return true
         end
         flush_counter = flush_counter - 1
         return flush_counter == 0
      end

      -- Wait for packets to be flushed to pcap.
      if #self.out_collect_app.packets ==
         expected_num_output_packets and
         #self.expected_collect_app.packets ==
         expected_num_output_packets then
         flush_counter = 5
      end
   end, no_report = true})

   -- Throw error outside of engine so that pcap files will be written to.
   if err then
      error(err)
   end

   for i = 1, expected_num_output_packets do
      local out_datagram = Datagram:new(self.out_collect_app.packets[i])
      local expected_datagram = Datagram:new(
         self.expected_collect_app.packets[i])
      local data, data_len = out_datagram:data()
      local cmp_data, cmp_data_len = expected_datagram:data()
      if data_len ~= cmp_data_len then
         error("Output packet #"..tostring(i).." length incorrect.")
      end
      for j = 0, data_len - 1 do
         if data[j] ~= cmp_data[j] then
            error("Output packet #"..tostring(i).." data does not match"..
            " expected packet data at index "..j..".")
         end
      end
   end

   print("Test passed!")
   print()

   self.out_collect_app:clear()
   self.expected_collect_app:clear()
end

function UnitTests:run()
   local go_interface = MockGoInterface:new({
      ipv4_backend = IPV4:pton(self.network_config.backend_addr),
      ipv6_backend = IPV6:pton(self.network_config.backend_ipv6_addr)
   })
   local rewriting_config = {
      src_mac = self.network_config.spike_mac,
      dst_mac = self.network_config.router_mac,
      ipv4_addr = self.network_config.spike_internal_addr,
      ipv6_addr = self.network_config.spike_internal_ipv6_addr,
      go_interface = go_interface
   }

   local c = config.new()
   config.app(c, "in_stream", TestStreamApp)

   config.app(c, "in_tee", B.Tee)
   config.app(c, "in_pcap_writer", P.PcapWriter, "test_in.pcap")
   config.app(c, "spike", Rewriting, rewriting_config)

   config.app(c, "out_tee", B.Tee)
   config.app(c, "out_pcap_writer", P.PcapWriter, "test_out.pcap")
   config.app(c, "out_collect", TestCollectApp)

   config.app(c, "expected_stream", TestStreamApp)
   config.app(c, "expected_tee", B.Tee)
   config.app(c, "expected_pcap_writer", P.PcapWriter, "test_expected.pcap")
   config.app(c, "expected_collect", TestCollectApp)

   config.link(c, "in_stream.output -> in_tee.input")
   config.link(c, "in_tee.output_pcap -> in_pcap_writer.input")
   config.link(c, "in_tee.output_spike -> spike.input")

   config.link(c, "spike.output -> out_tee.input")
   config.link(c, "out_tee.output_pcap -> out_pcap_writer.input")
   config.link(c, "out_tee.output_collect -> out_collect.input")

   config.link(c, "expected_stream.output -> expected_tee.input")
   config.link(c, "expected_tee.output_pcap -> expected_pcap_writer.input")
   config.link(c, "expected_tee.output_collect -> expected_collect.input")

   engine.configure(c)

   -- Note: app_table is undocumented, might break with Snabb updates.
   -- Another way to achieve this is to pass a callback function into
   -- the app constructor during config.app that passes a reference
   -- to the app out, though that would be a bit ugly.
   self.in_stream_app = engine.app_table["in_stream"]
   self.expected_stream_app = engine.app_table["expected_stream"]
   self.out_collect_app = engine.app_table["out_collect"]
   self.expected_collect_app = engine.app_table["expected_collect"]

   self:run_test("single_packet_ipv4", {
      [1] = self.synthesis:make_in_packet_normal()
   }, {
      [1] = self.synthesis:make_out_packet_normal()
   })

   self:run_test("ipv4_fragments",
      self.synthesis:make_in_packets_redirected_ipv4_fragments(), {
      [1] = self.synthesis:make_out_packet_normal()
   })

   go_interface.use_ipv6 = true
   self:run_test("single_packet_ipv6", {
      [1] = self.synthesis:make_in_packet_normal()
   }, {
      [1] = self.synthesis:make_out_packet_normal({
            outer_l3_prot = L3_IPV6,
      })
   })
end

return UnitTests
