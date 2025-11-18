# frozen_string_literal: true

# RubyNetStack - A userspace network stack implementation in pure Ruby
# 
# This module provides low-level network programming capabilities,
# interfacing directly with network cards using PF_PACKET and SOCK_RAW,
# bypassing the OS transport layer.

module RubyNetStack
  VERSION = "0.1.0"
  
  # Ethernet protocol constants
  ETH_P_ALL = 0x0003  # All protocols
  ETH_P_IP  = 0x0800  # Internet Protocol
  ETH_P_ARP = 0x0806  # Address Resolution Protocol
  
  # Socket family constants
  PF_PACKET = 17      # Packet family
  SOCK_RAW  = 3       # Raw socket type
  
  def self.version
    VERSION
  end
end

# Require all the stack components
require_relative "ruby_net_stack/raw_socket"
require_relative "ruby_net_stack/network_interface"
require_relative "ruby_net_stack/ethernet_frame"
require_relative "ruby_net_stack/hex_presenter"
require_relative "ruby_net_stack/ip_packet"
require_relative "ruby_net_stack/ip_address"
require_relative "ruby_net_stack/checksum"
require_relative "ruby_net_stack/arp_packet"
require_relative "ruby_net_stack/packet_dispatcher"
require_relative "ruby_net_stack/udp_datagram"
require_relative "ruby_net_stack/icmp_message"
require_relative "ruby_net_stack/tcp_segment"
require_relative "ruby_net_stack/tcp_connection_manager"
require_relative "ruby_net_stack/advanced_routing_table"
require_relative "ruby_net_stack/network_firewall"
require_relative "ruby_net_stack/qos_manager"
require_relative "ruby_net_stack/dns_resolver"
require_relative "ruby_net_stack/monitoring_support"
require_relative "ruby_net_stack/network_monitor"