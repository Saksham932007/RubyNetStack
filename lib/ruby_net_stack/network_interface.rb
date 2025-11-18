# frozen_string_literal: true

module RubyNetStack
  # NetworkInterface provides utilities for interacting with network interfaces
  # using ioctl system calls to get interface information
  class NetworkInterface
    # ioctl request constants for network interface operations
    SIOCGIFINDEX = 0x8933  # Get interface index
    SIOCGIFFLAGS = 0x8913  # Get interface flags
    SIOCGIFHWADDR = 0x8927 # Get hardware address (MAC)
    
    # Interface flags
    IFF_UP = 0x1           # Interface is up
    IFF_RUNNING = 0x40     # Interface is running
    
    attr_reader :name, :index, :mac_address
    
    def initialize(name)
      @name = name
      @index = nil
      @mac_address = nil
      fetch_interface_info
    end
    
    # Get the interface index using ioctl SIOCGIFINDEX
    # This is required for binding raw sockets to specific interfaces
    def self.get_interface_index(socket, interface_name)
      # Create ifreq structure: 16 bytes interface name + 4 bytes for index
      # struct ifreq {
      #   char ifr_name[IFNAMSIZ]; // 16 bytes
      #   union {
      #     int ifr_ifindex;       // 4 bytes
      #   } ifr_ifru;
      # }
      
      ifreq = [interface_name].pack("a16") + "\x00" * 4
      
      begin
        # Perform ioctl system call to get interface index
        result = socket.ioctl(SIOCGIFINDEX, ifreq)
        
        # Extract the interface index from the returned structure
        # The index is stored in bytes 16-19 of the ifreq structure
        index = result[16, 4].unpack1("I")
        
        puts "Interface '#{interface_name}' has index: #{index}"
        return index
      rescue Errno::ENODEV
        puts "Error: Network interface '#{interface_name}' not found"
        return nil
      rescue StandardError => e
        puts "Error getting interface index: #{e.message}"
        return nil
      end
    end
    
    # Get the MAC address of the interface using ioctl SIOCGIFHWADDR
    def self.get_mac_address(socket, interface_name)
      ifreq = [interface_name].pack("a16") + "\x00" * 8
      
      begin
        result = socket.ioctl(SIOCGIFHWADDR, ifreq)
        
        # Extract MAC address from sa_data field (offset 18, 6 bytes)
        mac_bytes = result[18, 6].unpack("C6")
        mac_address = mac_bytes.map { |b| sprintf("%02x", b) }.join(":")
        
        puts "Interface '#{interface_name}' MAC address: #{mac_address}"
        return mac_address
      rescue StandardError => e
        puts "Error getting MAC address: #{e.message}"
        return nil
      end
    end
    
    # Check if interface is up and running
    def self.interface_up?(socket, interface_name)
      ifreq = [interface_name].pack("a16") + "\x00" * 4
      
      begin
        result = socket.ioctl(SIOCGIFFLAGS, ifreq)
        flags = result[16, 2].unpack1("S")
        
        up = (flags & IFF_UP) != 0
        running = (flags & IFF_RUNNING) != 0
        
        puts "Interface '#{interface_name}' - UP: #{up}, RUNNING: #{running}"
        return up && running
      rescue StandardError => e
        puts "Error checking interface status: #{e.message}"
        return false
      end
    end
    
    private
    
    def fetch_interface_info
      # We'll populate this when we have a socket available
      puts "NetworkInterface initialized for: #{@name}"
    end
  end
end