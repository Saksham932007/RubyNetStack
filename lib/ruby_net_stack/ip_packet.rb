# frozen_string_literal: true

module RubyNetStack
  # IPPacket represents an IPv4 packet for parsing and constructing
  # raw IP packets. This is the network layer (Layer 3) of our stack.
  class IPPacket
    attr_reader :version, :ihl, :tos, :total_length, :identification, :flags, 
                :fragment_offset, :ttl, :protocol, :checksum, :src_ip, :dest_ip,
                :options, :payload, :raw_data
    
    # IP header constants
    MIN_HEADER_SIZE = 20    # Minimum IP header size (no options)
    MAX_HEADER_SIZE = 60    # Maximum IP header size (with options)
    VERSION_IPV4 = 4        # IPv4 version number
    
    # IP Protocol numbers
    PROTOCOL_ICMP = 1       # Internet Control Message Protocol
    PROTOCOL_TCP = 6        # Transmission Control Protocol  
    PROTOCOL_UDP = 17       # User Datagram Protocol
    
    # IP flags
    FLAG_DONT_FRAGMENT = 0x02  # Don't Fragment flag
    FLAG_MORE_FRAGMENTS = 0x01 # More Fragments flag
    
    def initialize(raw_data = nil)
      @raw_data = raw_data
      parse_packet if raw_data
    end
    
    # Parse raw IP packet bytes
    def parse_packet
      return false if @raw_data.length < MIN_HEADER_SIZE
      
      # IP Header Structure (20-60 bytes):
      # 0:     Version (4 bits) | IHL (4 bits)
      # 1:     Type of Service (8 bits)
      # 2-3:   Total Length (16 bits)
      # 4-5:   Identification (16 bits)
      # 6-7:   Flags (3 bits) | Fragment Offset (13 bits)
      # 8:     Time to Live (8 bits)
      # 9:     Protocol (8 bits)
      # 10-11: Header Checksum (16 bits)
      # 12-15: Source IP Address (32 bits)
      # 16-19: Destination IP Address (32 bits)
      # 20+:   Options (variable) + Payload
      
      # Parse first byte: Version and IHL (Internet Header Length)
      version_ihl = @raw_data[0].unpack1("C")
      @version = (version_ihl >> 4) & 0x0F  # Upper 4 bits
      @ihl = version_ihl & 0x0F            # Lower 4 bits
      
      # Validate IPv4 and header length
      return false unless @version == VERSION_IPV4
      header_length = @ihl * 4
      return false if header_length < MIN_HEADER_SIZE || header_length > MAX_HEADER_SIZE
      return false if @raw_data.length < header_length
      
      # Parse remaining header fields
      @tos = @raw_data[1].unpack1("C")
      @total_length = @raw_data[2, 2].unpack1("n")  # network byte order
      @identification = @raw_data[4, 2].unpack1("n")
      
      # Parse flags and fragment offset
      flags_frag = @raw_data[6, 2].unpack1("n")
      @flags = (flags_frag >> 13) & 0x07      # Upper 3 bits
      @fragment_offset = flags_frag & 0x1FFF  # Lower 13 bits
      
      @ttl = @raw_data[8].unpack1("C")
      @protocol = @raw_data[9].unpack1("C")  
      @checksum = @raw_data[10, 2].unpack1("n")
      
      # Parse IP addresses (4 bytes each)
      @src_ip = @raw_data[12, 4]
      @dest_ip = @raw_data[16, 4]
      
      # Parse options (if any)
      options_length = header_length - MIN_HEADER_SIZE
      @options = options_length > 0 ? @raw_data[20, options_length] : ""
      
      # Extract payload
      @payload = @raw_data[header_length..-1] || ""
      
      true
    end
    
    # Get header length in bytes
    def header_length
      @ihl ? @ihl * 4 : 0
    end
    
    # Check if packet is fragmented
    def fragmented?
      fragment_offset > 0 || more_fragments?
    end
    
    # Check More Fragments flag
    def more_fragments?
      (@flags & FLAG_MORE_FRAGMENTS) != 0
    end
    
    # Check Don't Fragment flag  
    def dont_fragment?
      (@flags & FLAG_DONT_FRAGMENT) != 0
    end
    
    # Get protocol description
    def protocol_description
      case @protocol
      when PROTOCOL_ICMP
        "ICMP"
      when PROTOCOL_TCP
        "TCP"
      when PROTOCOL_UDP
        "UDP"
      else
        "Unknown (#{@protocol})"
      end
    end
    
    # Check if packet contains specific protocol
    def icmp?
      @protocol == PROTOCOL_ICMP
    end
    
    def tcp?
      @protocol == PROTOCOL_TCP
    end
    
    def udp?
      @protocol == PROTOCOL_UDP
    end
    
    # Format IP address for display
    def format_ip(ip_bytes)
      IPAddress.bytes_to_string(ip_bytes)
    end
    
    # Get source IP as string
    def src_ip_str
      format_ip(@src_ip)
    end
    
    # Get destination IP as string  
    def dest_ip_str
      format_ip(@dest_ip)
    end
    
    # Get source IP as integer
    def src_ip_int
      IPAddress.bytes_to_int(@src_ip)
    end
    
    # Get destination IP as integer
    def dest_ip_int  
      IPAddress.bytes_to_int(@dest_ip)
    end
    
    # Get packet information as string
    def to_s
      return "Invalid IP Packet" unless @version
      
      "IP Packet:\n" +
      "  Version: #{@version}\n" +
      "  Header Length: #{header_length} bytes (IHL: #{@ihl})\n" +
      "  Type of Service: 0x#{sprintf('%02x', @tos)}\n" +
      "  Total Length: #{@total_length} bytes\n" +
      "  Identification: 0x#{sprintf('%04x', @identification)}\n" +
      "  Flags: 0x#{sprintf('%x', @flags)} (DF: #{dont_fragment?}, MF: #{more_fragments?})\n" +
      "  Fragment Offset: #{@fragment_offset}\n" +
      "  Time to Live: #{@ttl}\n" +
      "  Protocol: #{protocol_description} (#{@protocol})\n" +
      "  Header Checksum: 0x#{sprintf('%04x', @checksum)}\n" +
      "  Source IP: #{src_ip_str}\n" +
      "  Destination IP: #{dest_ip_str}\n" +
      "  Options: #{@options.length} bytes\n" +
      "  Payload: #{@payload.length} bytes"
    end
    
    # Detailed inspection
    def inspect
      return "#<IPPacket:invalid>" unless @version
      
      "#<IPPacket " +
      "#{src_ip_str}->#{dest_ip_str} " +
      "proto=#{protocol_description} " +
      "len=#{@total_length} " +
      "payload=#{@payload.length}b>"
    end
  end
end