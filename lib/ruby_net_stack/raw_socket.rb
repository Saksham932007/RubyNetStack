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
      puts "Ready to capture and process raw network packets"
      
      # Basic packet capture loop (will be expanded later)
      loop do
        data, = @socket.recvfrom(65536)
        puts "Received #{data.length} bytes"
        # For now, just show we're receiving data
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
    end
  end
end