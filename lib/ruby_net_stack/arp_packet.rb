# frozen_string_literal: true

module RubyNetStack
  # ARPPacket represents an Address Resolution Protocol packet for parsing and constructing
  # ARP packets. ARP is used to map IP addresses to MAC addresses on local networks.
  class ARPPacket
    attr_reader :hardware_type, :protocol_type, :hardware_size, :protocol_size,
                :opcode, :sender_mac, :sender_ip, :target_mac, :target_ip, :raw_data
    
    # ARP constants
    HARDWARE_ETHERNET = 1       # Ethernet hardware type
    PROTOCOL_IP = 0x0800       # IPv4 protocol type
    
    # ARP opcodes
    OPCODE_REQUEST = 1         # ARP Request
    OPCODE_REPLY = 2          # ARP Reply
    
    # ARP packet size
    ARP_PACKET_SIZE = 28       # Fixed size for Ethernet/IPv4 ARP
    
    def initialize(raw_data = nil)
      @raw_data = raw_data
      parse_packet if raw_data
    end
    
    # Parse raw ARP packet bytes
    def parse_packet
      return false if @raw_data.length < ARP_PACKET_SIZE
      
      # ARP Packet Structure (28 bytes for Ethernet/IPv4):
      # 0-1:   Hardware Type (16 bits)
      # 2-3:   Protocol Type (16 bits)  
      # 4:     Hardware Address Length (8 bits)
      # 5:     Protocol Address Length (8 bits)
      # 6-7:   Opcode (16 bits)
      # 8-13:  Sender Hardware Address (6 bytes for Ethernet)
      # 14-17: Sender Protocol Address (4 bytes for IPv4)
      # 18-23: Target Hardware Address (6 bytes for Ethernet)
      # 24-27: Target Protocol Address (4 bytes for IPv4)
      
      @hardware_type = @raw_data[0, 2].unpack1("n")
      @protocol_type = @raw_data[2, 2].unpack1("n")
      @hardware_size = @raw_data[4].unpack1("C")
      @protocol_size = @raw_data[5].unpack1("C")
      @opcode = @raw_data[6, 2].unpack1("n")
      
      # Validate this is Ethernet/IPv4 ARP
      return false unless @hardware_type == HARDWARE_ETHERNET
      return false unless @protocol_type == PROTOCOL_IP
      return false unless @hardware_size == 6  # MAC address length
      return false unless @protocol_size == 4  # IPv4 address length
      
      @sender_mac = @raw_data[8, 6]
      @sender_ip = @raw_data[14, 4]
      @target_mac = @raw_data[18, 6]
      @target_ip = @raw_data[24, 4]
      
      true
    end
    
    # Check if this is an ARP request
    def request?
      @opcode == OPCODE_REQUEST
    end
    
    # Check if this is an ARP reply
    def reply?
      @opcode == OPCODE_REPLY
    end
    
    # Get opcode description
    def opcode_description
      case @opcode
      when OPCODE_REQUEST
        "Request"
      when OPCODE_REPLY
        "Reply"
      else
        "Unknown (#{@opcode})"
      end
    end
    
    # Format MAC address for display
    def format_mac(mac_bytes)
      return "00:00:00:00:00:00" unless mac_bytes && mac_bytes.length == 6
      mac_bytes.unpack("C6").map { |b| sprintf("%02x", b) }.join(":")
    end
    
    # Format IP address for display
    def format_ip(ip_bytes)
      IPAddress.bytes_to_string(ip_bytes)
    end
    
    # Get sender MAC as string
    def sender_mac_str
      format_mac(@sender_mac)
    end
    
    # Get sender IP as string
    def sender_ip_str
      format_ip(@sender_ip)
    end
    
    # Get target MAC as string
    def target_mac_str
      format_mac(@target_mac)
    end
    
    # Get target IP as string
    def target_ip_str
      format_ip(@target_ip)
    end
    
    # Check if target MAC is broadcast (all zeros for requests)
    def target_mac_broadcast?
      @target_mac == "\x00\x00\x00\x00\x00\x00"
    end
    
    # Get packet information as string
    def to_s
      return "Invalid ARP Packet" unless @hardware_type
      
      "ARP Packet:\n" +
      "  Hardware Type: #{@hardware_type} (Ethernet)\n" +
      "  Protocol Type: 0x#{sprintf('%04x', @protocol_type)} (IPv4)\n" +
      "  Hardware Size: #{@hardware_size} bytes\n" +
      "  Protocol Size: #{@protocol_size} bytes\n" +
      "  Opcode: #{opcode_description} (#{@opcode})\n" +
      "  Sender MAC: #{sender_mac_str}\n" +
      "  Sender IP: #{sender_ip_str}\n" +
      "  Target MAC: #{target_mac_str}#{target_mac_broadcast? ? ' (broadcast)' : ''}\n" +
      "  Target IP: #{target_ip_str}"
    end
    
    # Get ARP operation summary
    def operation_summary
      if request?
        "Who has #{target_ip_str}? Tell #{sender_ip_str} (#{sender_mac_str})"
      elsif reply?
        "#{sender_ip_str} is at #{sender_mac_str}"
      else
        "Unknown ARP operation (opcode #{@opcode})"
      end
    end
    
    # Detailed inspection
    def inspect
      return "#<ARPPacket:invalid>" unless @hardware_type
      
      "#<ARPPacket " +
      "#{opcode_description.downcase} " +
      "#{sender_ip_str}(#{sender_mac_str}) -> #{target_ip_str}(#{target_mac_str})>"
    end
    
    # Create an ARP request packet
    def self.create_request(sender_mac, sender_ip, target_ip)
      packet = new
      packet.instance_variable_set(:@hardware_type, HARDWARE_ETHERNET)
      packet.instance_variable_set(:@protocol_type, PROTOCOL_IP)
      packet.instance_variable_set(:@hardware_size, 6)
      packet.instance_variable_set(:@protocol_size, 4)
      packet.instance_variable_set(:@opcode, OPCODE_REQUEST)
      packet.instance_variable_set(:@sender_mac, parse_mac_to_bytes(sender_mac))
      packet.instance_variable_set(:@sender_ip, IPAddress.string_to_bytes(sender_ip))
      packet.instance_variable_set(:@target_mac, "\x00" * 6)  # Unknown, seeking this
      packet.instance_variable_set(:@target_ip, IPAddress.string_to_bytes(target_ip))
      packet
    end
    
    # Create an ARP reply packet
    def self.create_reply(sender_mac, sender_ip, target_mac, target_ip)
      packet = new
      packet.instance_variable_set(:@hardware_type, HARDWARE_ETHERNET)
      packet.instance_variable_set(:@protocol_type, PROTOCOL_IP)
      packet.instance_variable_set(:@hardware_size, 6)
      packet.instance_variable_set(:@protocol_size, 4)
      packet.instance_variable_set(:@opcode, OPCODE_REPLY)
      packet.instance_variable_set(:@sender_mac, parse_mac_to_bytes(sender_mac))
      packet.instance_variable_set(:@sender_ip, IPAddress.string_to_bytes(sender_ip))
      packet.instance_variable_set(:@target_mac, parse_mac_to_bytes(target_mac))
      packet.instance_variable_set(:@target_ip, IPAddress.string_to_bytes(target_ip))
      packet
    end
    
    # Pack ARP packet for transmission
    def pack
      [
        @hardware_type,
        @protocol_type,
        @hardware_size,
        @protocol_size,
        @opcode
      ].pack("nnCCn") + @sender_mac + @sender_ip + @target_mac + @target_ip
    end
    
    private
    
    # Convert MAC address string to binary bytes (class method version)
    def self.parse_mac_to_bytes(mac_string)
      mac_string.split(":").map { |hex| hex.to_i(16) }.pack("C6")
    end
  end
end