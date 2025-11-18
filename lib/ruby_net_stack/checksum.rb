# frozen_string_literal: true

module RubyNetStack
  # Checksum provides utilities for calculating and validating Internet checksums
  # as defined in RFC 1071. This is used for IP, UDP, TCP, and ICMP checksums.
  class Checksum
    
    # Calculate the Internet checksum for the given data
    # Returns the 16-bit one's complement checksum
    def self.calculate(data)
      return 0 if data.nil? || data.empty?
      
      # Ensure data length is even by padding with zero if needed
      if data.length.odd?
        data = data + "\x00"
      end
      
      # Sum all 16-bit words in network byte order
      sum = 0
      (0...data.length).step(2) do |i|
        # Extract 16-bit word in network byte order (big endian)
        word = data[i, 2].unpack1("n")
        sum += word
      end
      
      # Add carry bits until no more carries
      while (sum >> 16) > 0
        sum = (sum & 0xFFFF) + (sum >> 16)
      end
      
      # Return one's complement (bitwise NOT) of the final sum
      (~sum) & 0xFFFF
    end
    
    # Verify checksum by calculating it and checking if result is 0
    def self.verify(data)
      calculate(data) == 0
    end
    
    # Calculate IP header checksum
    # IP header checksum covers only the header, not the payload
    def self.ip_checksum(ip_header)
      # The checksum field should be set to 0 before calculation
      header = ip_header.dup
      
      # Set checksum field (bytes 10-11) to zero
      header[10, 2] = "\x00\x00"
      
      calculate(header)
    end
    
    # Verify IP header checksum
    def self.verify_ip_checksum(ip_header)
      calculated = ip_checksum(ip_header)
      actual = ip_header[10, 2].unpack1("n")
      calculated == actual
    end
    
    # Calculate UDP checksum including pseudo-header
    # UDP checksum covers UDP header + data + pseudo-header
    def self.udp_checksum(src_ip, dest_ip, udp_packet)
      # Create pseudo-header for UDP checksum calculation
      # Pseudo-header: src_ip(4) + dest_ip(4) + zero(1) + protocol(1) + udp_length(2)
      pseudo_header = src_ip + dest_ip + "\x00" + [17].pack("C") + [udp_packet.length].pack("n")
      
      # Combine pseudo-header with UDP packet (header + data)
      checksum_data = pseudo_header + udp_packet
      
      calculate(checksum_data)
    end
    
    # Verify UDP checksum
    def self.verify_udp_checksum(src_ip, dest_ip, udp_packet)
      # UDP checksum is optional for IPv4 - if it's 0, skip verification
      actual_checksum = udp_packet[6, 2].unpack1("n")
      return true if actual_checksum == 0
      
      # Set checksum field to 0 for calculation
      test_packet = udp_packet.dup
      test_packet[6, 2] = "\x00\x00"
      
      calculated = udp_checksum(src_ip, dest_ip, test_packet)
      calculated == actual_checksum
    end
    
    # Calculate TCP checksum including pseudo-header
    def self.tcp_checksum(src_ip, dest_ip, tcp_packet)
      # Create pseudo-header for TCP checksum calculation
      # Pseudo-header: src_ip(4) + dest_ip(4) + zero(1) + protocol(1) + tcp_length(2)
      pseudo_header = src_ip + dest_ip + "\x00" + [6].pack("C") + [tcp_packet.length].pack("n")
      
      # Combine pseudo-header with TCP packet
      checksum_data = pseudo_header + tcp_packet
      
      calculate(checksum_data)
    end
    
    # Calculate ICMP checksum (simpler - no pseudo-header needed)
    def self.icmp_checksum(icmp_packet)
      # Set checksum field (bytes 2-3) to zero before calculation
      test_packet = icmp_packet.dup
      test_packet[2, 2] = "\x00\x00"
      
      calculate(test_packet)
    end
    
    # Verify ICMP checksum
    def self.verify_icmp_checksum(icmp_packet)
      actual_checksum = icmp_packet[2, 2].unpack1("n")
      calculated = icmp_checksum(icmp_packet)
      calculated == actual_checksum
    end
    
    # Generic checksum verification that automatically detects protocol
    def self.verify_packet_checksum(ip_packet_data)
      return false if ip_packet_data.length < 20
      
      # Extract IP header
      ihl = (ip_packet_data[0].unpack1("C") & 0x0F) * 4
      ip_header = ip_packet_data[0, ihl]
      
      # Verify IP header checksum
      unless verify_ip_checksum(ip_header)
        puts "IP header checksum verification failed"
        return false
      end
      
      # Get protocol and verify transport layer checksum if present
      protocol = ip_packet_data[9].unpack1("C")
      payload = ip_packet_data[ihl..-1]
      
      case protocol
      when 17 # UDP
        if payload.length >= 8
          src_ip = ip_packet_data[12, 4]
          dest_ip = ip_packet_data[16, 4]
          return verify_udp_checksum(src_ip, dest_ip, payload)
        end
      when 1 # ICMP
        return verify_icmp_checksum(payload) if payload.length >= 8
      when 6 # TCP
        if payload.length >= 20
          src_ip = ip_packet_data[12, 4]
          dest_ip = ip_packet_data[16, 4]
          # TCP checksum verification would go here
          # For now, just verify IP checksum
        end
      end
      
      true
    end
    
    # Utility method to display checksum information
    def self.checksum_info(data, expected = nil)
      calculated = calculate(data)
      
      info = "Calculated checksum: 0x#{sprintf('%04x', calculated)}"
      
      if expected
        info += ", Expected: 0x#{sprintf('%04x', expected)}"
        info += ", Valid: #{calculated == expected}"
      end
      
      info
    end
  end
end