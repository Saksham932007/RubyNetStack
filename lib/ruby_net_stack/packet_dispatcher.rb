# frozen_string_literal: true

module RubyNetStack
  # PacketDispatcher routes ethernet frames to appropriate protocol handlers
  # based on EtherType and manages the parsing pipeline
  class PacketDispatcher
    attr_reader :stats
    
    def initialize
      @stats = {
        total_packets: 0,
        ethernet_frames: 0,
        ip_packets: 0,
        arp_packets: 0,
        unknown_packets: 0,
        invalid_packets: 0
      }
    end
    
    # Main dispatch method - routes ethernet frame to appropriate handler
    def dispatch(raw_data)
      @stats[:total_packets] += 1
      
      # Parse ethernet frame first
      ethernet_frame = EthernetFrame.new(raw_data)
      
      unless ethernet_frame.dest_mac
        @stats[:invalid_packets] += 1
        return { type: :invalid, data: nil, frame: nil }
      end
      
      @stats[:ethernet_frames] += 1
      
      # Route based on EtherType
      case ethernet_frame.ethertype
      when EthernetFrame::ETHERTYPE_IP
        handle_ip_packet(ethernet_frame)
      when EthernetFrame::ETHERTYPE_ARP
        handle_arp_packet(ethernet_frame)
      else
        @stats[:unknown_packets] += 1
        { type: :unknown, data: nil, frame: ethernet_frame }
      end
    end
    
    # Handle IP packets
    def handle_ip_packet(ethernet_frame)
      ip_packet = IPPacket.new(ethernet_frame.payload)
      
      if ip_packet.version == IPPacket::VERSION_IPV4
        @stats[:ip_packets] += 1
        
        # Further dispatch based on IP protocol
        transport_result = dispatch_transport_layer(ip_packet)
        
        {
          type: :ip,
          data: ip_packet,
          frame: ethernet_frame,
          transport: transport_result
        }
      else
        @stats[:invalid_packets] += 1
        { type: :invalid_ip, data: ip_packet, frame: ethernet_frame }
      end
    end
    
    # Handle ARP packets
    def handle_arp_packet(ethernet_frame)
      arp_packet = ARPPacket.new(ethernet_frame.payload)
      
      if arp_packet.hardware_type == ARPPacket::HARDWARE_ETHERNET
        @stats[:arp_packets] += 1
        
        {
          type: :arp,
          data: arp_packet,
          frame: ethernet_frame
        }
      else
        @stats[:invalid_packets] += 1
        { type: :invalid_arp, data: arp_packet, frame: ethernet_frame }
      end
    end
    
    # Dispatch transport layer protocols (UDP, TCP, ICMP)
    def dispatch_transport_layer(ip_packet)
      case ip_packet.protocol
      when IPPacket::PROTOCOL_UDP
        udp_datagram = UDPDatagram.new(ip_packet.payload)
        if udp_datagram.src_port
          { type: :udp, data: udp_datagram, parsed: true }
        else
          { type: :udp, data: nil, parsed: false }
        end
      when IPPacket::PROTOCOL_TCP
        { type: :tcp, data: nil, parsed: false }
      when IPPacket::PROTOCOL_ICMP
        icmp_message = ICMPMessage.new(ip_packet.payload)
        if icmp_message.type
          { type: :icmp, data: icmp_message, parsed: true }
        else
          { type: :icmp, data: nil, parsed: false }
        end
      else
        { type: :unknown_transport, data: nil, parsed: false }
      end
    end
    
    # Get statistics summary
    def stats_summary
      total = @stats[:total_packets]
      return "No packets processed" if total == 0
      
      "Packet Statistics:\n" +
      "  Total: #{total}\n" +
      "  Ethernet: #{@stats[:ethernet_frames]} (#{percentage(@stats[:ethernet_frames], total)}%)\n" +
      "  IP: #{@stats[:ip_packets]} (#{percentage(@stats[:ip_packets], total)}%)\n" +
      "  ARP: #{@stats[:arp_packets]} (#{percentage(@stats[:arp_packets], total)}%)\n" +
      "  Unknown: #{@stats[:unknown_packets]} (#{percentage(@stats[:unknown_packets], total)}%)\n" +
      "  Invalid: #{@stats[:invalid_packets]} (#{percentage(@stats[:invalid_packets], total)}%)"
    end
    
    # Reset statistics
    def reset_stats
      @stats.each_key { |key| @stats[key] = 0 }
    end
    
    # Format packet result for display
    def format_result(result)
      case result[:type]
      when :ip
        format_ip_result(result)
      when :arp
        format_arp_result(result)
      when :unknown
        format_unknown_result(result)
      when :invalid
        "Invalid ethernet frame"
      else
        "Unknown packet type: #{result[:type]}"
      end
    end
    
    private
    
    def percentage(value, total)
      return 0 if total == 0
      ((value.to_f / total) * 100).round(1)
    end
    
    def format_ip_result(result)
      frame = result[:frame]
      ip_packet = result[:data]
      transport = result[:transport]
      
      output = "#{frame.to_s}\n\n#{ip_packet.to_s}"
      
      if transport[:parsed]
        output += "\n\n#{transport[:data].to_s}"
      else
        output += "\n  Transport Protocol: #{transport[:type].to_s.upcase}"
      end
      
      output
    end
    
    def format_arp_result(result)
      frame = result[:frame]
      arp_packet = result[:data]
      
      "#{frame.to_s}\n\n#{arp_packet.to_s}\n  Operation: #{arp_packet.operation_summary}"
    end
    
    def format_unknown_result(result)
      frame = result[:frame]
      "#{frame.to_s}\n  Unknown Protocol - EtherType: 0x#{sprintf('%04x', frame.ethertype)}"
    end
  end
end