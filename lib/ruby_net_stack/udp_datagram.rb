# frozen_string_literal: true

module RubyNetStack
  # UDPDatagram represents a UDP packet for parsing and constructing
  # UDP datagrams. This is part of the transport layer (Layer 4).
  class UDPDatagram
    attr_reader :src_port, :dest_port, :length, :checksum, :payload, :raw_data
    
    # UDP header constants
    UDP_HEADER_SIZE = 8
    
    def initialize(raw_data = nil)
      @raw_data = raw_data
      parse_datagram if raw_data
    end
    
    # Parse raw UDP datagram bytes
    def parse_datagram
      return false if @raw_data.length < UDP_HEADER_SIZE
      
      # UDP Header Structure (8 bytes):
      # 0-1:   Source Port (16 bits)
      # 2-3:   Destination Port (16 bits)
      # 4-5:   Length (16 bits)
      # 6-7:   Checksum (16 bits)
      # 8+:    Payload
      
      @src_port = @raw_data[0, 2].unpack1("n")
      @dest_port = @raw_data[2, 2].unpack1("n")
      @length = @raw_data[4, 2].unpack1("n")
      @checksum = @raw_data[6, 2].unpack1("n")
      
      # Validate length
      return false if @length < UDP_HEADER_SIZE
      return false if @length > @raw_data.length
      
      @payload = @raw_data[8, @length - UDP_HEADER_SIZE] || ""
      
      true
    end
    
    # Verify UDP checksum (optional for IPv4)
    def valid_checksum?(src_ip, dest_ip)
      return true if @checksum == 0  # Checksum is optional for IPv4
      
      Checksum.verify_udp_checksum(src_ip, dest_ip, @raw_data)
    end
    
    # Get payload as string (handling binary data safely)
    def payload_string(encoding = 'UTF-8')
      return "" if @payload.empty?
      
      begin
        @payload.force_encoding(encoding)
        @payload.valid_encoding? ? @payload : @payload.inspect
      rescue
        @payload.inspect
      end
    end
    
    # Check if payload contains printable text
    def payload_printable?
      return false if @payload.empty?
      
      # Check if at least 80% of payload is printable ASCII
      printable_count = @payload.bytes.count { |b| b >= 32 && b <= 126 }
      (printable_count.to_f / @payload.length) >= 0.8
    end
    
    # Get service name for well-known ports
    def src_port_service
      port_to_service(@src_port)
    end
    
    def dest_port_service
      port_to_service(@dest_port)
    end
    
    # Convert to string representation
    def to_s
      return "Invalid UDP Datagram" unless @src_port
      
      payload_info = if payload_printable?
        "\"#{payload_string.strip}\"[#{@payload.length}b]"
      else
        "binary[#{@payload.length}b]"
      end
      
      "UDP Datagram:\n" +
      "  Source Port: #{@src_port} (#{src_port_service})\n" +
      "  Destination Port: #{@dest_port} (#{dest_port_service})\n" +
      "  Length: #{@length} bytes\n" +
      "  Checksum: 0x#{sprintf('%04x', @checksum)}#{@checksum == 0 ? ' (not used)' : ''}\n" +
      "  Payload: #{payload_info}"
    end
    
    # Pack UDP datagram for transmission  
    def pack(src_ip = nil, dest_ip = nil)
      return nil unless @src_port && @dest_port
      
      @payload ||= ""
      length = UDP_HEADER_SIZE + @payload.length
      
      # Calculate checksum if IP addresses provided
      checksum_val = 0
      if src_ip && dest_ip
        temp_header = [@src_port, @dest_port, length, 0].pack("nnnn")
        temp_packet = temp_header + @payload
        checksum_val = Checksum.udp_checksum(IPAddress.string_to_bytes(src_ip), 
                                            IPAddress.string_to_bytes(dest_ip), 
                                            temp_packet)
      end
      
      [@src_port, @dest_port, length, checksum_val].pack("nnnn") + @payload
    end
    
    # Create UDP datagram for transmission
    def self.create(src_port, dest_port, payload = "")
      datagram = new
      datagram.instance_variable_set(:@src_port, src_port)
      datagram.instance_variable_set(:@dest_port, dest_port)
      datagram.instance_variable_set(:@payload, payload)
      datagram
    end
    
    private
    
    def port_to_service(port)
      case port
      when 20 then "ftp-data"
      when 21 then "ftp"
      when 22 then "ssh"
      when 23 then "telnet"
      when 25 then "smtp"
      when 53 then "dns"
      when 67 then "dhcp-server"
      when 68 then "dhcp-client"
      when 80 then "http"
      when 110 then "pop3"
      when 143 then "imap"
      when 443 then "https"
      when 993 then "imaps"
      when 995 then "pop3s"
      when 4321 then "ruby-net-stack"
      else "unknown"
      end
    end
  end
end