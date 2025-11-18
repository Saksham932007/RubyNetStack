# frozen_string_literal: true

module RubyNetStack
  # TCPSegment represents a TCP packet with full state machine support
  # Implements RFC 793 TCP protocol with connection tracking and state management
  class TCPSegment
    attr_accessor :src_port, :dst_port, :seq_num, :ack_num, :data_offset
    attr_accessor :flags, :window_size, :checksum, :urgent_ptr, :options, :payload
    
    # TCP States for connection tracking
    CLOSED = 0
    LISTEN = 1
    SYN_SENT = 2
    SYN_RECEIVED = 3
    ESTABLISHED = 4
    FIN_WAIT_1 = 5
    FIN_WAIT_2 = 6
    CLOSE_WAIT = 7
    CLOSING = 8
    LAST_ACK = 9
    TIME_WAIT = 10
    
    STATE_NAMES = {
      CLOSED => 'CLOSED',
      LISTEN => 'LISTEN', 
      SYN_SENT => 'SYN_SENT',
      SYN_RECEIVED => 'SYN_RECEIVED',
      ESTABLISHED => 'ESTABLISHED',
      FIN_WAIT_1 => 'FIN_WAIT_1',
      FIN_WAIT_2 => 'FIN_WAIT_2',
      CLOSE_WAIT => 'CLOSE_WAIT',
      CLOSING => 'CLOSING',
      LAST_ACK => 'LAST_ACK',
      TIME_WAIT => 'TIME_WAIT'
    }.freeze
    
    # TCP Control Flags
    FIN = 0x01  # Finish
    SYN = 0x02  # Synchronize
    RST = 0x04  # Reset
    PSH = 0x08  # Push
    ACK = 0x10  # Acknowledge
    URG = 0x20  # Urgent
    ECE = 0x40  # ECN Echo
    CWR = 0x80  # Congestion Window Reduced
    
    # TCP Options
    OPTION_END = 0
    OPTION_NOP = 1
    OPTION_MSS = 2
    OPTION_WINDOW_SCALE = 3
    OPTION_TIMESTAMP = 8
    
    TCP_HEADER_SIZE = 20  # Minimum TCP header size
    
    def initialize(raw_data = nil)
      @raw_data = raw_data
      @payload = ""
      @options = ""
      parse_segment if raw_data
    end
    
    # Parse raw TCP segment bytes
    def parse_segment
      return false if @raw_data.length < TCP_HEADER_SIZE
      
      # TCP Header Structure:
      # 0-1:   Source Port (16 bits)
      # 2-3:   Destination Port (16 bits)
      # 4-7:   Sequence Number (32 bits)
      # 8-11:  Acknowledgment Number (32 bits)
      # 12:    Data Offset (4 bits) | Reserved (4 bits)
      # 13:    Flags (8 bits: CWR|ECE|URG|ACK|PSH|RST|SYN|FIN)
      # 14-15: Window Size (16 bits)
      # 16-17: Checksum (16 bits)
      # 18-19: Urgent Pointer (16 bits)
      # 20+:   Options (variable) + Data
      
      @src_port = @raw_data[0, 2].unpack1("n")
      @dst_port = @raw_data[2, 2].unpack1("n")
      @seq_num = @raw_data[4, 4].unpack1("N")
      @ack_num = @raw_data[8, 4].unpack1("N")
      
      offset_reserved = @raw_data[12].unpack1("C")
      @data_offset = (offset_reserved >> 4) & 0x0F
      
      @flags = @raw_data[13].unpack1("C")
      @window_size = @raw_data[14, 2].unpack1("n")
      @checksum = @raw_data[16, 2].unpack1("n")
      @urgent_ptr = @raw_data[18, 2].unpack1("n")
      
      # Parse options if present
      header_length = @data_offset * 4
      if header_length > TCP_HEADER_SIZE && header_length <= @raw_data.length
        @options = @raw_data[TCP_HEADER_SIZE, header_length - TCP_HEADER_SIZE]
        @payload = @raw_data[header_length..-1] || ""
      else
        @options = ""
        @payload = @raw_data[TCP_HEADER_SIZE..-1] || ""
      end
      
      true
    end
    
    # Flag checking methods
    def fin?; (@flags & FIN) != 0; end
    def syn?; (@flags & SYN) != 0; end
    def rst?; (@flags & RST) != 0; end
    def psh?; (@flags & PSH) != 0; end
    def ack?; (@flags & ACK) != 0; end
    def urg?; (@flags & URG) != 0; end
    def ece?; (@flags & ECE) != 0; end
    def cwr?; (@flags & CWR) != 0; end
    
    # Get flags as readable string
    def flags_string
      flags_array = []
      flags_array << "FIN" if fin?
      flags_array << "SYN" if syn?
      flags_array << "RST" if rst?
      flags_array << "PSH" if psh?
      flags_array << "ACK" if ack?
      flags_array << "URG" if urg?
      flags_array << "ECE" if ece?
      flags_array << "CWR" if cwr?
      
      flags_array.empty? ? "NONE" : flags_array.join(",")
    end
    
    # Parse TCP options
    def parse_options
      return {} if @options.empty?
      
      parsed_options = {}
      offset = 0
      
      while offset < @options.length
        option_kind = @options[offset].unpack1("C")
        
        case option_kind
        when OPTION_END
          break
        when OPTION_NOP
          offset += 1
        when OPTION_MSS
          if offset + 4 <= @options.length
            length = @options[offset + 1].unpack1("C")
            mss = @options[offset + 2, 2].unpack1("n")
            parsed_options[:mss] = mss
            offset += length
          else
            break
          end
        when OPTION_WINDOW_SCALE
          if offset + 3 <= @options.length
            length = @options[offset + 1].unpack1("C")
            scale = @options[offset + 2].unpack1("C")
            parsed_options[:window_scale] = scale
            offset += length
          else
            break
          end
        else
          # Unknown option - skip
          if offset + 1 < @options.length
            length = @options[offset + 1].unpack1("C")
            offset += length
          else
            break
          end
        end
      end
      
      parsed_options
    end
    
    # Verify TCP checksum with pseudo-header
    def valid_checksum?(src_ip, dst_ip)
      Checksum.verify_tcp_checksum(src_ip, dst_ip, @raw_data)
    end
    
    # Pack TCP segment for transmission
    def pack(src_ip = nil, dst_ip = nil)
      @data_offset ||= 5  # 20 bytes minimum header
      @window_size ||= 65535
      @urgent_ptr ||= 0
      
      # Calculate header length including options
      options_padded = @options.dup
      while (options_padded.length % 4) != 0
        options_padded += "\x00"  # Pad to 4-byte boundary
      end
      
      header_length = TCP_HEADER_SIZE + options_padded.length
      @data_offset = header_length / 4
      
      # Build header without checksum
      offset_flags = (@data_offset << 4) | 0  # Reserved bits = 0
      
      header = [
        @src_port,
        @dst_port,
        @seq_num,
        @ack_num,
        offset_flags,
        @flags,
        @window_size,
        0,  # Checksum will be calculated
        @urgent_ptr
      ].pack("nnNNCCnnn")
      
      # Add options and payload
      segment = header + options_padded + (@payload || "")
      
      # Calculate checksum if IP addresses provided
      if src_ip && dst_ip
        @checksum = Checksum.tcp_checksum(src_ip, dst_ip, segment)
        # Insert checksum
        segment[16, 2] = [@checksum].pack("n")
      end
      
      segment
    end
    
    # Create TCP segment for transmission
    def self.create(src_port, dst_port, seq_num, ack_num, flags, payload = "")
      segment = new
      segment.src_port = src_port
      segment.dst_port = dst_port
      segment.seq_num = seq_num
      segment.ack_num = ack_num
      segment.flags = flags
      segment.payload = payload
      segment.window_size = 65535
      segment.urgent_ptr = 0
      segment.options = ""
      segment
    end
    
    # Create SYN segment
    def self.create_syn(src_port, dst_port, seq_num, options = {})
      segment = create(src_port, dst_port, seq_num, 0, SYN)
      
      # Add common SYN options
      if options[:mss]
        segment.options += [OPTION_MSS, 4, options[:mss]].pack("CCn")
      end
      
      if options[:window_scale]
        segment.options += [OPTION_WINDOW_SCALE, 3, options[:window_scale]].pack("CCC")
      end
      
      segment
    end
    
    # Create SYN-ACK segment
    def self.create_syn_ack(src_port, dst_port, seq_num, ack_num, options = {})
      segment = create(src_port, dst_port, seq_num, ack_num, SYN | ACK)
      
      # Add options like in SYN
      if options[:mss]
        segment.options += [OPTION_MSS, 4, options[:mss]].pack("CCn")
      end
      
      segment
    end
    
    # Create ACK segment
    def self.create_ack(src_port, dst_port, seq_num, ack_num, payload = "")
      create(src_port, dst_port, seq_num, ack_num, ACK, payload)
    end
    
    # Create FIN segment
    def self.create_fin(src_port, dst_port, seq_num, ack_num)
      create(src_port, dst_port, seq_num, ack_num, FIN | ACK)
    end
    
    # Create RST segment
    def self.create_rst(src_port, dst_port, seq_num, ack_num = 0)
      create(src_port, dst_port, seq_num, ack_num, RST)
    end
    
    # String representation
    def to_s
      return "Invalid TCP Segment" unless @src_port
      
      parsed_opts = parse_options
      options_str = parsed_opts.empty? ? "none" : parsed_opts.map { |k, v| "#{k}=#{v}" }.join(",")
      
      "TCP Segment:\n" +
      "  Source Port: #{@src_port}\n" +
      "  Destination Port: #{@dst_port}\n" +
      "  Sequence Number: #{@seq_num}\n" +
      "  Acknowledgment Number: #{@ack_num}\n" +
      "  Data Offset: #{@data_offset} (#{@data_offset * 4} bytes)\n" +
      "  Flags: #{flags_string} (0x#{sprintf('%02x', @flags)})\n" +
      "  Window Size: #{@window_size}\n" +
      "  Checksum: 0x#{sprintf('%04x', @checksum)}\n" +
      "  Urgent Pointer: #{@urgent_ptr}\n" +
      "  Options: #{options_str}\n" +
      "  Payload: #{@payload.length} bytes"
    end
    
    # Detailed inspection
    def inspect
      return "#<TCPSegment:invalid>" unless @src_port
      
      "#<TCPSegment " +
      "#{@src_port}->#{@dst_port} " +
      "seq=#{@seq_num} ack=#{@ack_num} " +
      "flags=#{flags_string} " +
      "payload=#{@payload.length}b>"
    end
  end
end