# frozen_string_literal: true

require 'socket'

module RubyNetStack
  # RawSocket provides low-level network access using PF_PACKET sockets
  # This allows us to send and receive raw ethernet frames, bypassing
  # the kernel's network stack
  class RawSocket
    attr_reader :socket, :interface_name, :interface_index
    
    def initialize(interface = "eth0")
      @interface_name = interface
      @interface_index = nil
      puts "RubyNetStack v#{RubyNetStack::VERSION} - Raw Socket Network Stack"
      puts "Initializing userspace network stack for interface: #{@interface_name}"
      create_raw_socket
      get_interface_info
    end
    
    def start
      puts "Starting network stack on #{@interface_name}"
      puts "Socket created successfully: #{@socket.class}"
      puts "Interface index: #{@interface_index}"
      puts "Socket bound to interface: #{@interface_name}"
      puts "Ready to capture and process raw network packets"
      
      # Enhanced packet capture loop with ethernet frame parsing
      loop do
        data, = @socket.recvfrom(65536)
        
        # Parse the ethernet frame
        frame = EthernetFrame.new(data)
        
        if frame.dest_mac
          puts "\n" + "="*50
          puts frame.to_s
          puts "="*50
        else
          puts "Received invalid ethernet frame (#{data.length} bytes)"
        end
        
        break if data.length == 0
      end
    rescue Interrupt
      puts "\nShutting down network stack..."
      close
    end
    
    def close
      @socket&.close
      puts "Raw socket closed"
    end
    
    private
    
    # Create a raw packet socket using PF_PACKET family
    # This allows us to receive all ethernet frames on the interface
    def create_raw_socket
      begin
        # Socket.open(family, type, protocol)
        # PF_PACKET = 17, SOCK_RAW = 3, ETH_P_ALL = 0x0003
        @socket = Socket.open(Socket::PF_PACKET, Socket::SOCK_RAW, RubyNetStack::ETH_P_ALL)
        puts "Raw packet socket created successfully"
      rescue Errno::EPERM
        puts "Error: Permission denied. Raw sockets require root privileges."
        puts "Please run with sudo"
        exit 1
      rescue Errno::EPROTONOSUPPORT
        puts "Error: Protocol not supported. PF_PACKET may not be available."
        exit 1
      rescue StandardError => e
        puts "Error creating raw socket: #{e.message}"
        exit 1
      end
    end
    
    # Get interface information using ioctl calls
    def get_interface_info
      @interface_index = NetworkInterface.get_interface_index(@socket, @interface_name)
      
      if @interface_index.nil?
        puts "Failed to get interface index for #{@interface_name}"
        close
        exit 1
      end
      
      # Check if interface is up and running
      unless NetworkInterface.interface_up?(@socket, @interface_name)
        puts "Warning: Interface #{@interface_name} may not be up and running"
      end
      
      # Get MAC address for future use
      NetworkInterface.get_mac_address(@socket, @interface_name)
      
      # Bind socket to the specific interface
      bind_to_interface
    end
    
    # Bind the raw socket to a specific network interface using sockaddr_ll
    def bind_to_interface
      # struct sockaddr_ll {
      #   unsigned short sll_family;   // AF_PACKET = 17
      #   unsigned short sll_protocol; // ETH_P_ALL = 0x0003  
      #   int            sll_ifindex;   // Interface index
      #   unsigned short sll_hatype;   // Hardware type (not used for bind)
      #   unsigned char  sll_pkttype;  // Packet type (not used for bind)
      #   unsigned char  sll_halen;    // Hardware address length
      #   unsigned char  sll_addr[8];  // Hardware address (not used for bind)
      # };
      
      # Pack sockaddr_ll structure for binding
      # S = unsigned short (2 bytes), I = int (4 bytes), C = unsigned char (1 byte)
      sockaddr_ll = [
        Socket::AF_PACKET,           # sll_family (2 bytes)
        RubyNetStack::ETH_P_ALL,    # sll_protocol (2 bytes) 
        @interface_index,            # sll_ifindex (4 bytes)
        0,                          # sll_hatype (2 bytes) - not needed for bind
        0,                          # sll_pkttype (1 byte) - not needed for bind
        0,                          # sll_halen (1 byte) - not needed for bind
        0, 0, 0, 0, 0, 0, 0, 0      # sll_addr[8] (8 bytes) - not needed for bind
      ].pack("SSISCC8")
      
      begin
        @socket.bind(sockaddr_ll)
        puts "Successfully bound socket to interface #{@interface_name} (index: #{@interface_index})"
      rescue Errno::ENODEV
        puts "Error: Interface #{@interface_name} not available for binding"
        close
        exit 1
      rescue StandardError => e
        puts "Error binding socket to interface: #{e.message}"
        close
        exit 1
      end
    end
  end
end