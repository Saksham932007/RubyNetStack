# frozen_string_literal: true

module RubyNetStack
  # IPAddress provides utilities for converting between different IP address formats
  # This handles conversion between binary, integer, and dotted decimal representations
  class IPAddress
    
    # Convert 4 bytes of binary data to dotted decimal string (e.g., "192.168.1.1")
    def self.bytes_to_string(bytes)
      return "0.0.0.0" unless bytes && bytes.length == 4
      bytes.unpack("C4").join(".")
    end
    
    # Convert dotted decimal string to 4 bytes of binary data
    def self.string_to_bytes(ip_string)
      begin
        parts = ip_string.split(".")
        return nil unless parts.length == 4
        
        # Validate each octet is 0-255
        octets = parts.map { |part| Integer(part) }
        return nil unless octets.all? { |octet| octet >= 0 && octet <= 255 }
        
        octets.pack("C4")
      rescue ArgumentError
        nil
      end
    end
    
    # Convert 4 bytes of binary data to 32-bit integer (host byte order)
    def self.bytes_to_int(bytes)
      return 0 unless bytes && bytes.length == 4
      bytes.unpack1("N")  # Network byte order to host
    end
    
    # Convert 32-bit integer to 4 bytes of binary data (network byte order)
    def self.int_to_bytes(ip_int)
      [ip_int].pack("N")
    end
    
    # Convert dotted decimal string to 32-bit integer
    def self.string_to_int(ip_string)
      bytes = string_to_bytes(ip_string)
      bytes ? bytes_to_int(bytes) : 0
    end
    
    # Convert 32-bit integer to dotted decimal string
    def self.int_to_string(ip_int)
      bytes = int_to_bytes(ip_int)
      bytes_to_string(bytes)
    end
    
    # Check if IP address is in a private range
    def self.private?(ip_string)
      ip_int = string_to_int(ip_string)
      
      # 10.0.0.0/8 (Class A private)
      return true if ip_int >= string_to_int("10.0.0.0") && ip_int <= string_to_int("10.255.255.255")
      
      # 172.16.0.0/12 (Class B private)  
      return true if ip_int >= string_to_int("172.16.0.0") && ip_int <= string_to_int("172.31.255.255")
      
      # 192.168.0.0/16 (Class C private)
      return true if ip_int >= string_to_int("192.168.0.0") && ip_int <= string_to_int("192.168.255.255")
      
      false
    end
    
    # Check if IP address is localhost/loopback
    def self.localhost?(ip_string)
      ip_int = string_to_int(ip_string)
      # 127.0.0.0/8 range
      ip_int >= string_to_int("127.0.0.0") && ip_int <= string_to_int("127.255.255.255")
    end
    
    # Check if IP address is multicast
    def self.multicast?(ip_string)
      ip_int = string_to_int(ip_string)
      # 224.0.0.0/4 range (Class D)
      ip_int >= string_to_int("224.0.0.0") && ip_int <= string_to_int("239.255.255.255")
    end
    
    # Check if IP address is broadcast
    def self.broadcast?(ip_string)
      ip_string == "255.255.255.255"
    end
    
    # Get network and broadcast addresses for a given IP/subnet
    def self.network_info(ip_string, subnet_mask)
      ip_int = string_to_int(ip_string)
      mask_int = string_to_int(subnet_mask)
      
      network_int = ip_int & mask_int
      broadcast_int = network_int | (~mask_int & 0xFFFFFFFF)
      
      {
        network: int_to_string(network_int),
        broadcast: int_to_string(broadcast_int),
        netmask: subnet_mask,
        host_count: (~mask_int & 0xFFFFFFFF) - 1  # Subtract network and broadcast
      }
    end
    
    # Convert CIDR notation to subnet mask
    def self.cidr_to_mask(cidr_bits)
      return "0.0.0.0" if cidr_bits < 0 || cidr_bits > 32
      
      mask_int = (0xFFFFFFFF << (32 - cidr_bits)) & 0xFFFFFFFF
      int_to_string(mask_int)
    end
    
    # Convert subnet mask to CIDR notation
    def self.mask_to_cidr(subnet_mask)
      mask_int = string_to_int(subnet_mask)
      
      # Count consecutive 1 bits from the left
      cidr = 0
      test_bit = 0x80000000
      
      while test_bit > 0 && (mask_int & test_bit) != 0
        cidr += 1
        test_bit >>= 1
      end
      
      cidr
    end
    
    # Validate IP address format
    def self.valid?(ip_string)
      return false unless ip_string.is_a?(String)
      
      parts = ip_string.split(".")
      return false unless parts.length == 4
      
      parts.all? do |part|
        begin
          octet = Integer(part)
          octet >= 0 && octet <= 255
        rescue ArgumentError
          false
        end
      end
    end
  end
end