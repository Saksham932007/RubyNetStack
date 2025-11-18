# frozen_string_literal: true

module RubyNetStack
  # EthernetFrame represents an Ethernet II frame for parsing and constructing
  # raw ethernet packets. This is the data link layer (Layer 2) of our stack.
  class EthernetFrame
    attr_reader :dest_mac, :src_mac, :ethertype, :payload, :raw_data
    
    # Ethernet frame constants
    ETH_HEADER_SIZE = 14  # 6 + 6 + 2 bytes
    MIN_FRAME_SIZE = 64   # Minimum ethernet frame size
    MAX_FRAME_SIZE = 1518 # Maximum ethernet frame size
    
    # Common EtherType values
    ETHERTYPE_IP = 0x0800   # Internet Protocol version 4
    ETHERTYPE_ARP = 0x0806  # Address Resolution Protocol
    ETHERTYPE_IPV6 = 0x86DD # Internet Protocol version 6
    
    def initialize(raw_data = nil)
      @raw_data = raw_data
      parse_frame if raw_data
    end
    
    # Parse raw ethernet frame bytes
    def parse_frame
      return false if @raw_data.length < ETH_HEADER_SIZE
      
      # Ethernet Header Structure:
      # 0-5:   Destination MAC (6 bytes)
      # 6-11:  Source MAC (6 bytes) 
      # 12-13: EtherType (2 bytes, network byte order)
      # 14+:   Payload
      
      @dest_mac = parse_mac_address(@raw_data[0, 6])
      @src_mac = parse_mac_address(@raw_data[6, 6])
      @ethertype = @raw_data[12, 2].unpack1("n") # network byte order (big endian)
      @payload = @raw_data[14..-1] || ""
      
      true
    end
    
    # Convert 6 bytes to MAC address string format
    def parse_mac_address(bytes)
      bytes.unpack("C6").map { |b| sprintf("%02x", b) }.join(":")
    end
    
    # Get human-readable EtherType description
    def ethertype_description
      case @ethertype
      when ETHERTYPE_IP
        "IPv4"
      when ETHERTYPE_ARP
        "ARP" 
      when ETHERTYPE_IPV6
        "IPv6"
      else
        sprintf("Unknown (0x%04x)", @ethertype)
      end
    end
    
    # Check if this frame contains IP traffic
    def ip?
      @ethertype == ETHERTYPE_IP
    end
    
    # Check if this frame contains ARP traffic
    def arp?
      @ethertype == ETHERTYPE_ARP
    end
    
    # Check if frame size is valid
    def valid_size?
      return false unless @raw_data
      size = @raw_data.length
      size >= MIN_FRAME_SIZE && size <= MAX_FRAME_SIZE
    end
    
    # Get frame information as string
    def to_s
      return "Invalid Ethernet Frame" unless @dest_mac
      
      "Ethernet Frame:\n" +
      "  Destination MAC: #{@dest_mac}\n" +
      "  Source MAC: #{@src_mac}\n" +
      "  EtherType: #{ethertype_description} (0x#{sprintf('%04x', @ethertype)})\n" +
      "  Payload Size: #{@payload.length} bytes\n" +
      "  Frame Size: #{@raw_data&.length || 0} bytes"
    end
    
    # Get hex dump of frame for debugging
    def hex_dump(show_payload = true)
      return "No raw data available" unless @raw_data
      
      result = "Ethernet Frame Hex Dump:\n"
      result += "Header (14 bytes):\n"
      result += HexPresenter.hex_dump(@raw_data[0, 14], 16, true)
      
      if show_payload && @payload.length > 0
        result += "\n\nPayload (#{@payload.length} bytes):\n"
        # Show first 64 bytes of payload to avoid overwhelming output
        payload_to_show = @payload[0, 64]
        result += HexPresenter.hex_dump(payload_to_show, 16, true)
        result += "\n... (truncated)" if @payload.length > 64
      end
      
      result
    end
    
    # Detailed inspection of frame
    def inspect
      return "#<EthernetFrame:invalid>" unless @dest_mac
      
      "#<EthernetFrame " +
      "#{@src_mac}->#{@dest_mac} " +
      "type=#{ethertype_description} " + 
      "payload=#{@payload.length}b>"
    end
  end
end