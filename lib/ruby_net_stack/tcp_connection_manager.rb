# frozen_string_literal: true

module RubyNetStack
  # TCPConnectionManager manages TCP connections with full state machine support
  # Implements connection tracking, state transitions, and flow control
  class TCPConnectionManager
    attr_reader :connections, :listening_ports
    
    def initialize(raw_socket)
      @raw_socket = raw_socket
      @connections = {}  # key: "src_ip:src_port->dst_ip:dst_port"
      @listening_ports = {}  # port => callback
      @sequence_numbers = {}
      @connection_mutex = Mutex.new
    end
    
    # Add a listening port with callback
    def listen(port, &callback)
      @listening_ports[port] = callback
      puts "TCP listening on port #{port}"
    end
    
    # Stop listening on a port
    def stop_listening(port)
      @listening_ports.delete(port)
      puts "Stopped listening on port #{port}"
    end
    
    # Process incoming TCP segment
    def process_tcp_segment(ethernet_frame, ip_packet, tcp_segment)
      connection_id = build_connection_id(
        ip_packet.src_ip_str, tcp_segment.src_port,
        ip_packet.dest_ip_str, tcp_segment.dst_port
      )
      
      @connection_mutex.synchronize do
        connection = @connections[connection_id]
        
        if connection
          # Existing connection - process according to state
          process_existing_connection(connection, ethernet_frame, ip_packet, tcp_segment)
        else
          # New connection attempt
          process_new_connection(connection_id, ethernet_frame, ip_packet, tcp_segment)
        end
      end
    end
    
    # Initiate outbound TCP connection
    def connect(dest_ip, dest_port, src_port = nil)
      src_port ||= allocate_ephemeral_port
      our_ip = @raw_socket.get_interface_ip
      
      connection_id = build_connection_id(our_ip, src_port, dest_ip, dest_port)
      
      # Create connection object
      connection = TCPConnection.new(
        src_ip: our_ip,
        src_port: src_port,
        dst_ip: dest_ip,
        dst_port: dest_port,
        state: TCPSegment::SYN_SENT,
        local_seq: generate_initial_seq_num,
        local_ack: 0
      )
      
      @connections[connection_id] = connection
      
      # Send SYN
      syn_segment = TCPSegment.create_syn(
        src_port, dest_port, connection.local_seq,
        { mss: 1460, window_scale: 7 }
      )
      
      send_tcp_segment(connection, syn_segment)
      connection.local_seq += 1  # SYN consumes sequence number
      
      connection
    end
    
    # Send data on established connection
    def send_data(connection_id, data)
      connection = @connections[connection_id]
      return false unless connection && connection.state == TCPSegment::ESTABLISHED
      
      # Fragment data if needed (simple implementation)
      data.bytes.each_slice(1460) do |chunk|
        payload = chunk.pack('C*')
        
        segment = TCPSegment.create_ack(
          connection.src_port, connection.dst_port,
          connection.local_seq, connection.local_ack,
          payload
        )
        
        send_tcp_segment(connection, segment)
        connection.local_seq += payload.length
      end
      
      true
    end
    
    # Close connection gracefully
    def close_connection(connection_id)
      connection = @connections[connection_id]
      return false unless connection
      
      case connection.state
      when TCPSegment::ESTABLISHED
        # Send FIN
        fin_segment = TCPSegment.create_fin(
          connection.src_port, connection.dst_port,
          connection.local_seq, connection.local_ack
        )
        
        send_tcp_segment(connection, fin_segment)
        connection.local_seq += 1  # FIN consumes sequence number
        connection.state = TCPSegment::FIN_WAIT_1
        
      when TCPSegment::CLOSE_WAIT
        # Send FIN (passive close)
        fin_segment = TCPSegment.create_fin(
          connection.src_port, connection.dst_port,
          connection.local_seq, connection.local_ack
        )
        
        send_tcp_segment(connection, fin_segment)
        connection.local_seq += 1
        connection.state = TCPSegment::LAST_ACK
      end
      
      true
    end
    
    # Reset connection immediately
    def reset_connection(connection_id, reason = "Reset by user")
      connection = @connections[connection_id]
      return false unless connection
      
      rst_segment = TCPSegment.create_rst(
        connection.src_port, connection.dst_port,
        connection.local_seq, connection.local_ack
      )
      
      send_tcp_segment(connection, rst_segment)
      @connections.delete(connection_id)
      
      puts "Connection #{connection_id} reset: #{reason}"
      true
    end
    
    # Get connection statistics
    def connection_stats
      states = Hash.new(0)
      @connections.each_value do |conn|
        state_name = TCPSegment::STATE_NAMES[conn.state] || "UNKNOWN"
        states[state_name] += 1
      end
      
      {
        total_connections: @connections.size,
        listening_ports: @listening_ports.keys,
        states: states
      }
    end
    
    # Cleanup old connections (TIME_WAIT, etc.)
    def cleanup_connections
      @connection_mutex.synchronize do
        now = Time.now
        @connections.delete_if do |id, conn|
          # Remove TIME_WAIT connections after 2 minutes
          if conn.state == TCPSegment::TIME_WAIT
            (now - conn.state_changed_at) > 120
          elsif conn.state == TCPSegment::CLOSED
            true  # Remove closed connections immediately
          else
            false
          end
        end
      end
    end
    
    private
    
    def process_existing_connection(connection, ethernet_frame, ip_packet, tcp_segment)
      # Validate sequence numbers
      unless valid_sequence?(connection, tcp_segment)
        puts "Invalid sequence number for connection #{connection.connection_id}"
        return
      end
      
      # Update remote sequence numbers
      if tcp_segment.ack?
        connection.remote_ack = tcp_segment.ack_num
      end
      
      if tcp_segment.payload.length > 0
        connection.remote_seq = tcp_segment.seq_num + tcp_segment.payload.length
      elsif tcp_segment.syn? || tcp_segment.fin?
        connection.remote_seq = tcp_segment.seq_num + 1
      else
        connection.remote_seq = tcp_segment.seq_num
      end
      
      # State machine processing
      case connection.state
      when TCPSegment::SYN_SENT
        handle_syn_sent(connection, tcp_segment)
      when TCPSegment::SYN_RECEIVED
        handle_syn_received(connection, tcp_segment)
      when TCPSegment::ESTABLISHED
        handle_established(connection, tcp_segment)
      when TCPSegment::FIN_WAIT_1
        handle_fin_wait_1(connection, tcp_segment)
      when TCPSegment::FIN_WAIT_2
        handle_fin_wait_2(connection, tcp_segment)
      when TCPSegment::CLOSE_WAIT
        handle_close_wait(connection, tcp_segment)
      when TCPSegment::CLOSING
        handle_closing(connection, tcp_segment)
      when TCPSegment::LAST_ACK
        handle_last_ack(connection, tcp_segment)
      when TCPSegment::TIME_WAIT
        handle_time_wait(connection, tcp_segment)
      end
    end
    
    def process_new_connection(connection_id, ethernet_frame, ip_packet, tcp_segment)
      if tcp_segment.syn? && !tcp_segment.ack?
        # Incoming SYN - check if we're listening
        callback = @listening_ports[tcp_segment.dst_port]
        if callback
          accept_connection(connection_id, ethernet_frame, ip_packet, tcp_segment, callback)
        else
          # Send RST - not listening
          send_rst_response(ethernet_frame, ip_packet, tcp_segment)
        end
      else
        # Not a valid new connection
        send_rst_response(ethernet_frame, ip_packet, tcp_segment)
      end
    end
    
    def accept_connection(connection_id, ethernet_frame, ip_packet, tcp_segment, callback)
      # Create new connection in SYN_RECEIVED state
      connection = TCPConnection.new(
        src_ip: ip_packet.dest_ip_str,
        src_port: tcp_segment.dst_port,
        dst_ip: ip_packet.src_ip_str,
        dst_port: tcp_segment.src_port,
        state: TCPSegment::SYN_RECEIVED,
        local_seq: generate_initial_seq_num,
        local_ack: tcp_segment.seq_num + 1,
        remote_seq: tcp_segment.seq_num + 1,
        callback: callback
      )
      
      @connections[connection_id] = connection
      
      # Send SYN-ACK
      syn_ack = TCPSegment.create_syn_ack(
        connection.src_port, connection.dst_port,
        connection.local_seq, connection.local_ack,
        { mss: 1460 }
      )
      
      send_tcp_segment(connection, syn_ack)
      connection.local_seq += 1  # SYN consumes sequence number
      
      puts "Accepted connection from #{ip_packet.src_ip_str}:#{tcp_segment.src_port}"
    end
    
    # State machine handlers
    def handle_syn_sent(connection, tcp_segment)
      if tcp_segment.syn? && tcp_segment.ack?
        # Received SYN-ACK
        connection.remote_seq = tcp_segment.seq_num + 1
        connection.local_ack = tcp_segment.seq_num + 1
        
        # Send ACK
        ack_segment = TCPSegment.create_ack(
          connection.src_port, connection.dst_port,
          connection.local_seq, connection.local_ack
        )
        
        send_tcp_segment(connection, ack_segment)
        transition_state(connection, TCPSegment::ESTABLISHED)
        
        puts "Connection established: #{connection.connection_id}"
      elsif tcp_segment.syn?
        # Simultaneous open
        connection.remote_seq = tcp_segment.seq_num + 1
        connection.local_ack = tcp_segment.seq_num + 1
        
        syn_ack = TCPSegment.create_syn_ack(
          connection.src_port, connection.dst_port,
          connection.local_seq, connection.local_ack
        )
        
        send_tcp_segment(connection, syn_ack)
        transition_state(connection, TCPSegment::SYN_RECEIVED)
      end
    end
    
    def handle_syn_received(connection, tcp_segment)
      if tcp_segment.ack? && !tcp_segment.syn?
        # Connection established
        transition_state(connection, TCPSegment::ESTABLISHED)
        
        # Notify callback
        if connection.callback
          Thread.new { connection.callback.call(connection) }
        end
        
        puts "Connection established: #{connection.connection_id}"
      elsif tcp_segment.rst?
        # Connection reset
        @connections.delete(connection.connection_id)
        puts "Connection reset during handshake: #{connection.connection_id}"
      end
    end
    
    def handle_established(connection, tcp_segment)
      # Handle data
      if tcp_segment.payload.length > 0
        puts "Received #{tcp_segment.payload.length} bytes on #{connection.connection_id}"
        
        # Send ACK for received data
        ack_segment = TCPSegment.create_ack(
          connection.src_port, connection.dst_port,
          connection.local_seq, connection.remote_seq
        )
        
        send_tcp_segment(connection, ack_segment)
        connection.local_ack = connection.remote_seq
        
        # Process data with callback
        if connection.callback
          Thread.new { connection.callback.call(connection, tcp_segment.payload) }
        end
      end
      
      # Handle FIN
      if tcp_segment.fin?
        # Received FIN - transition to CLOSE_WAIT
        connection.local_ack = connection.remote_seq
        
        ack_segment = TCPSegment.create_ack(
          connection.src_port, connection.dst_port,
          connection.local_seq, connection.local_ack
        )
        
        send_tcp_segment(connection, ack_segment)
        transition_state(connection, TCPSegment::CLOSE_WAIT)
        
        puts "Received FIN on #{connection.connection_id}, entering CLOSE_WAIT"
      end
    end
    
    def handle_fin_wait_1(connection, tcp_segment)
      if tcp_segment.ack? && tcp_segment.fin?
        # FIN-ACK received
        connection.local_ack = connection.remote_seq
        
        ack_segment = TCPSegment.create_ack(
          connection.src_port, connection.dst_port,
          connection.local_seq, connection.local_ack
        )
        
        send_tcp_segment(connection, ack_segment)
        transition_state(connection, TCPSegment::TIME_WAIT)
      elsif tcp_segment.ack?
        # Just ACK received
        transition_state(connection, TCPSegment::FIN_WAIT_2)
      elsif tcp_segment.fin?
        # Simultaneous close
        connection.local_ack = connection.remote_seq
        
        ack_segment = TCPSegment.create_ack(
          connection.src_port, connection.dst_port,
          connection.local_seq, connection.local_ack
        )
        
        send_tcp_segment(connection, ack_segment)
        transition_state(connection, TCPSegment::CLOSING)
      end
    end
    
    def handle_fin_wait_2(connection, tcp_segment)
      if tcp_segment.fin?
        connection.local_ack = connection.remote_seq
        
        ack_segment = TCPSegment.create_ack(
          connection.src_port, connection.dst_port,
          connection.local_seq, connection.local_ack
        )
        
        send_tcp_segment(connection, ack_segment)
        transition_state(connection, TCPSegment::TIME_WAIT)
      end
    end
    
    def handle_close_wait(connection, tcp_segment)
      # Application should close when ready
      # For now, close automatically after a delay
      Thread.new do
        sleep(1)  # Give app time to process
        close_connection(connection.connection_id)
      end
    end
    
    def handle_closing(connection, tcp_segment)
      if tcp_segment.ack?
        transition_state(connection, TCPSegment::TIME_WAIT)
      end
    end
    
    def handle_last_ack(connection, tcp_segment)
      if tcp_segment.ack?
        @connections.delete(connection.connection_id)
        puts "Connection closed: #{connection.connection_id}"
      end
    end
    
    def handle_time_wait(connection, tcp_segment)
      # Ignore segments in TIME_WAIT
      # Connection will be cleaned up by timer
    end
    
    # Helper methods
    def build_connection_id(src_ip, src_port, dst_ip, dst_port)
      "#{src_ip}:#{src_port}->#{dst_ip}:#{dst_port}"
    end
    
    def transition_state(connection, new_state)
      old_state = TCPSegment::STATE_NAMES[connection.state]
      new_state_name = TCPSegment::STATE_NAMES[new_state]
      
      connection.state = new_state
      connection.state_changed_at = Time.now
      
      puts "Connection #{connection.connection_id}: #{old_state} -> #{new_state_name}"
    end
    
    def valid_sequence?(connection, tcp_segment)
      # Simplified sequence validation
      # In production, this would be more sophisticated
      true
    end
    
    def send_tcp_segment(connection, tcp_segment)
      # Get interface MAC for source
      src_mac = @raw_socket.get_interface_mac
      
      # Build and send the complete packet
      tcp_data = tcp_segment.pack(
        IPAddress.string_to_bytes(connection.src_ip),
        IPAddress.string_to_bytes(connection.dst_ip)
      )
      
      @raw_socket.send_ip_packet(
        connection.dst_mac || "ff:ff:ff:ff:ff:ff",  # Would need ARP resolution
        src_mac,
        connection.src_ip,
        connection.dst_ip,
        IPPacket::PROTOCOL_TCP,
        tcp_data
      )
    end
    
    def send_rst_response(ethernet_frame, ip_packet, tcp_segment)
      rst_segment = TCPSegment.create_rst(
        tcp_segment.dst_port,
        tcp_segment.src_port,
        0,
        tcp_segment.seq_num + 1
      )
      
      tcp_data = rst_segment.pack(
        IPAddress.string_to_bytes(ip_packet.dest_ip_str),
        IPAddress.string_to_bytes(ip_packet.src_ip_str)
      )
      
      @raw_socket.send_ip_packet(
        ethernet_frame.src_mac,
        ethernet_frame.dest_mac,
        ip_packet.dest_ip_str,
        ip_packet.src_ip_str,
        IPPacket::PROTOCOL_TCP,
        tcp_data
      )
    end
    
    def generate_initial_seq_num
      Random.rand(0x80000000)
    end
    
    def allocate_ephemeral_port
      (49152..65535).to_a.sample
    end
  end
  
  # TCPConnection represents a single TCP connection
  class TCPConnection
    attr_accessor :src_ip, :src_port, :dst_ip, :dst_port, :dst_mac
    attr_accessor :state, :local_seq, :local_ack, :remote_seq, :remote_ack
    attr_accessor :callback, :state_changed_at
    
    def initialize(src_ip:, src_port:, dst_ip:, dst_port:, state:, local_seq:, local_ack:, 
                   remote_seq: 0, remote_ack: 0, callback: nil, dst_mac: nil)
      @src_ip = src_ip
      @src_port = src_port
      @dst_ip = dst_ip
      @dst_port = dst_port
      @dst_mac = dst_mac
      @state = state
      @local_seq = local_seq
      @local_ack = local_ack
      @remote_seq = remote_seq
      @remote_ack = remote_ack
      @callback = callback
      @state_changed_at = Time.now
    end
    
    def connection_id
      "#{@src_ip}:#{@src_port}->#{@dst_ip}:#{@dst_port}"
    end
    
    def state_name
      TCPSegment::STATE_NAMES[@state] || "UNKNOWN"
    end
    
    def to_s
      "TCP Connection #{connection_id} [#{state_name}] seq=#{@local_seq} ack=#{@local_ack}"
    end
  end
end