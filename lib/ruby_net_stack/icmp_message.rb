# frozen_string_literal: true

module RubyNetStack
  # ICMPMessage represents an ICMP packet for parsing and constructing
  # ICMP messages. This is used for network diagnostics and error reporting.
  class ICMPMessage
    attr_reader :type, :code, :checksum, :identifier, :sequence, :payload, :raw_data
    
    # ICMP message types
    TYPE_ECHO_REPLY = 0
    TYPE_ECHO_REQUEST = 8
    TYPE_DEST_UNREACHABLE = 3
    TYPE_TIME_EXCEEDED = 11
    
    # ICMP header size
    ICMP_HEADER_SIZE = 8
    
    def initialize(raw_data = nil)
      @raw_data = raw_data
      parse_message if raw_data
    end
    
    # Parse raw ICMP message bytes
    def parse_message
      return false if @raw_data.length < ICMP_HEADER_SIZE
      
      # ICMP Header Structure (8 bytes minimum):
      # 0:     Type (8 bits)
      # 1:     Code (8 bits) 
      # 2-3:   Checksum (16 bits)
      # 4-7:   Rest of header (depends on type)
      # 8+:    Payload
      
      @type = @raw_data[0].unpack1("C")
      @code = @raw_data[1].unpack1("C")
      @checksum = @raw_data[2, 2].unpack1("n")
      
      # For echo request/reply, bytes 4-7 contain identifier and sequence
      if echo_request? || echo_reply?
        @identifier = @raw_data[4, 2].unpack1("n")
        @sequence = @raw_data[6, 2].unpack1("n")
        @payload = @raw_data[8..-1] || ""
      else
        @identifier = 0
        @sequence = 0
        @payload = @raw_data[4..-1] || ""
      end
      
      true
    end
    
    # Check if this is an echo request (ping)
    def echo_request?
      @type == TYPE_ECHO_REQUEST
    end
    
    # Check if this is an echo reply (pong)
    def echo_reply?
      @type == TYPE_ECHO_REPLY
    end
    
    # Verify ICMP checksum
    def valid_checksum?
      Checksum.verify_icmp_checksum(@raw_data)
    end
    
    # Get type description
    def type_description
      case @type
      when TYPE_ECHO_REPLY
        "Echo Reply"
      when TYPE_ECHO_REQUEST
        "Echo Request" 
      when TYPE_DEST_UNREACHABLE
        "Destination Unreachable"
      when TYPE_TIME_EXCEEDED
        "Time Exceeded"
      else
        "Unknown (#{@type})"
      end
    end
    
    # Convert to string representation
    def to_s
      return "Invalid ICMP Message" unless @type
      
      result = "ICMP Message:\n" +
               "  Type: #{type_description} (#{@type})\n" +
               "  Code: #{@code}\n" +
               "  Checksum: 0x#{sprintf('%04x', @checksum)}\n"
      
      if echo_request? || echo_reply?
        result += "  Identifier: #{@identifier}\n" +
                  "  Sequence: #{@sequence}\n"
      end
      
      result += "  Payload: #{@payload.length} bytes"
      
      result
    end
    
    # Create echo reply from echo request
    def create_echo_reply
      return nil unless echo_request?
      
      # Create echo reply with same identifier, sequence, and payload
      reply_data = [TYPE_ECHO_REPLY, @code, 0, @identifier, @sequence].pack("CCnnn") + @payload
      
      # Calculate checksum
      checksum_val = Checksum.icmp_checksum(reply_data)
      reply_data[2, 2] = [checksum_val].pack("n")
      
      ICMPMessage.new(reply_data)
    end
    
    # Pack ICMP message for transmission
    def pack
      if echo_request? || echo_reply?
        header = [@type, @code, 0, @identifier, @sequence].pack("CCnnn")
      else
        header = [@type, @code, 0, 0].pack("CCnn")
      end
      
      packet = header + @payload
      checksum_val = Checksum.icmp_checksum(packet)
      packet[2, 2] = [checksum_val].pack("n")
      
      packet
    end
  end
end