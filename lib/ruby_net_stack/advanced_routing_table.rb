# frozen_string_literal: true

module RubyNetStack
  # AdvancedRoutingTable implements sophisticated routing with NAT, load balancing,
  # and multi-path routing capabilities
  class AdvancedRoutingTable
    attr_reader :routes, :nat_table, :connection_tracking, :load_balancer
    
    def initialize(default_interface = "eth0")
      @routes = []
      @nat_table = {}  # external_key => internal_mapping
      @connection_tracking = {}  # connection_id => connection_state
      @arp_cache = {}  # ip => mac mapping
      @default_interface = default_interface
      @external_ip = nil
      @route_metrics = {}
      @load_balancer = LoadBalancer.new
      @route_mutex = Mutex.new
    end
    
    # Add static route to routing table
    def add_route(network, netmask, gateway = nil, interface = nil, metric = 0, type: :static)
      interface ||= @default_interface
      
      route = {
        network: ip_to_int(network),
        netmask: ip_to_int(netmask),
        gateway: gateway ? ip_to_int(gateway) : nil,
        interface: interface,
        metric: metric,
        type: type,
        created_at: Time.now,
        active: true
      }
      
      @route_mutex.synchronize do
        @routes << route
        # Sort by specificity (longer netmask first), then by metric
        @routes.sort_by! { |r| [-(r[:netmask].to_s(2).count('1')), r[:metric]] }
      end
      
      puts "Added #{type} route: #{network}/#{netmask_to_cidr(netmask)} via #{gateway || interface} metric #{metric}"
    end
    
    # Add default route
    def add_default_route(gateway, interface = nil, metric = 0)
      add_route("0.0.0.0", "0.0.0.0", gateway, interface, metric, type: :default)
    end
    
    # Remove route
    def remove_route(network, netmask)
      @route_mutex.synchronize do
        @routes.reject! do |route|
          route[:network] == ip_to_int(network) && route[:netmask] == ip_to_int(netmask)
        end
      end
    end
    
    # Find best route for destination
    def find_route(dst_ip)
      dst_int = ip_to_int(dst_ip)
      
      @route_mutex.synchronize do
        # Find matching routes (longest prefix match)
        matching_routes = @routes.select do |route|
          route[:active] && ((dst_int & route[:netmask]) == route[:network])
        end
        
        # Return best route (already sorted by specificity and metric)
        matching_routes.first
      end
    end
    
    # Find all routes for destination (for load balancing)
    def find_all_routes(dst_ip)
      dst_int = ip_to_int(dst_ip)
      
      @route_mutex.synchronize do
        @routes.select do |route|
          route[:active] && ((dst_int & route[:netmask]) == route[:network])
        end
      end
    end
    
    # Get next hop for destination
    def get_next_hop(dst_ip)
      route = find_route(dst_ip)
      return nil unless route
      
      {
        next_hop: route[:gateway] ? int_to_ip(route[:gateway]) : dst_ip,
        interface: route[:interface],
        type: route[:type],
        metric: route[:metric]
      }
    end
    
    # Equal-Cost Multi-Path (ECMP) routing
    def get_ecmp_route(dst_ip, flow_hash = nil)
      routes = find_all_routes(dst_ip)
      return nil if routes.empty?
      
      # Group routes by metric
      best_metric = routes.map { |r| r[:metric] }.min
      best_routes = routes.select { |r| r[:metric] == best_metric }
      
      # Use flow hash for consistent routing
      if flow_hash && best_routes.size > 1
        index = flow_hash % best_routes.size
        best_routes[index]
      else
        best_routes.first
      end
    end
    
    # NAT (Network Address Translation) methods
    def configure_nat(internal_network, external_ip, external_interface)
      @external_ip = external_ip
      @external_interface = external_interface
      @internal_network = internal_network
      
      puts "Configured NAT: #{internal_network} -> #{external_ip} (#{external_interface})"
    end
    
    # SNAT (Source NAT) for outbound packets
    def apply_snat(packet, connection_id = nil)
      return packet unless @external_ip
      
      case packet
      when UDPDatagram
        # Create NAT mapping
        internal_key = "#{packet.src_ip}:#{packet.src_port}"
        external_port = allocate_external_port(packet.dst_port, :udp)
        external_key = "#{external_port}/udp"
        
        @nat_table[external_key] = {
          internal_ip: packet.src_ip,
          internal_port: packet.src_port,
          external_ip: @external_ip,
          external_port: external_port,
          protocol: :udp,
          created_at: Time.now,
          last_used: Time.now,
          connection_id: connection_id
        }
        
        # Modify packet
        packet.src_ip = @external_ip
        packet.src_port = external_port
        
      when TCPSegment
        # Similar for TCP
        internal_key = "#{packet.src_ip}:#{packet.src_port}"
        external_port = allocate_external_port(packet.dst_port, :tcp)
        external_key = "#{external_port}/tcp"
        
        @nat_table[external_key] = {
          internal_ip: packet.src_ip,
          internal_port: packet.src_port,
          external_ip: @external_ip,
          external_port: external_port,
          protocol: :tcp,
          created_at: Time.now,
          last_used: Time.now,
          connection_id: connection_id
        }
        
        packet.src_ip = @external_ip
        packet.src_port = external_port
      end
      
      packet
    end
    
    # DNAT (Destination NAT) for inbound packets
    def apply_dnat(packet)\n      return packet unless @external_ip\n      \n      case packet\n      when UDPDatagram\n        external_key = \"#{packet.dst_port}/udp\"\n        mapping = @nat_table[external_key]\n        \n        if mapping\n          packet.dst_ip = mapping[:internal_ip]\n          packet.dst_port = mapping[:internal_port]\n          mapping[:last_used] = Time.now\n        end\n        \n      when TCPSegment\n        external_key = \"#{packet.dst_port}/tcp\"\n        mapping = @nat_table[external_key]\n        \n        if mapping\n          packet.dst_ip = mapping[:internal_ip]\n          packet.dst_port = mapping[:internal_port]\n          mapping[:last_used] = Time.now\n        end\n      end\n      \n      packet\n    end
    
    # Port forwarding (static NAT rules)
    def add_port_forward(external_port, internal_ip, internal_port, protocol = :tcp)
      key = "#{external_port}/#{protocol}"
      
      @nat_table[key] = {
        internal_ip: internal_ip,
        internal_port: internal_port,
        external_ip: @external_ip,
        external_port: external_port,
        protocol: protocol,
        created_at: Time.now,
        last_used: Time.now,
        type: :static
      }
      
      puts "Added port forward: #{@external_ip}:#{external_port} -> #{internal_ip}:#{internal_port} (#{protocol})"
    end
    
    # Remove port forwarding
    def remove_port_forward(external_port, protocol = :tcp)
      key = "#{external_port}/#{protocol}"
      @nat_table.delete(key)
      puts "Removed port forward: #{external_port}/#{protocol}"
    end
    
    # Connection tracking for stateful inspection
    def track_connection(src_ip, src_port, dst_ip, dst_port, protocol, state = :new)
      connection_id = "#{src_ip}:#{src_port}->#{dst_ip}:#{dst_port}/#{protocol}"
      
      @connection_tracking[connection_id] = {
        src_ip: src_ip,
        src_port: src_port,
        dst_ip: dst_ip,
        dst_port: dst_port,
        protocol: protocol,
        state: state,
        created_at: Time.now,
        last_seen: Time.now,
        bytes_sent: 0,
        bytes_received: 0,
        packets_sent: 0,
        packets_received: 0
      }
      
      connection_id
    end
    
    # Update connection state
    def update_connection(connection_id, bytes: 0, packets: 1, direction: :outbound)
      connection = @connection_tracking[connection_id]
      return unless connection
      
      connection[:last_seen] = Time.now
      
      if direction == :outbound
        connection[:bytes_sent] += bytes
        connection[:packets_sent] += packets
      else
        connection[:bytes_received] += bytes
        connection[:packets_received] += packets
      end
    end
    
    # Check if connection exists and is valid
    def connection_exists?(connection_id)
      connection = @connection_tracking[connection_id]
      return false unless connection
      
      # Check if connection is too old (timeout)
      case connection[:protocol]
      when :tcp
        (Time.now - connection[:last_seen]) < 3600  # 1 hour for TCP
      when :udp
        (Time.now - connection[:last_seen]) < 300   # 5 minutes for UDP
      when :icmp
        (Time.now - connection[:last_seen]) < 60    # 1 minute for ICMP
      else
        false
      end
    end
    
    # ARP cache management
    def add_arp_entry(ip, mac, interface = nil)
      @arp_cache[ip] = {
        mac: mac,
        interface: interface || @default_interface,
        timestamp: Time.now,
        type: :dynamic
      }
    end
    
    def get_arp_entry(ip)
      entry = @arp_cache[ip]
      return nil unless entry
      
      # Check if entry is still valid (5 minutes for dynamic entries)
      if entry[:type] == :dynamic && (Time.now - entry[:timestamp]) > 300
        @arp_cache.delete(ip)
        return nil
      end
      
      entry
    end
    
    # Route maintenance and monitoring
    def cleanup_expired_entries
      now = Time.now
      
      # Clean NAT table
      @nat_table.delete_if do |key, mapping|
        next false if mapping[:type] == :static  # Keep static mappings
        
        # Remove inactive dynamic mappings
        (now - mapping[:last_used]) > 300  # 5 minutes
      end
      
      # Clean connection tracking
      @connection_tracking.delete_if do |id, connection|
        !connection_exists?(id)
      end
      
      # Clean ARP cache
      @arp_cache.delete_if do |ip, entry|
        entry[:type] == :dynamic && (now - entry[:timestamp]) > 300
      end
    end
    
    # Routing statistics
    def get_stats
      {
        total_routes: @routes.size,
        active_routes: @routes.count { |r| r[:active] },
        nat_mappings: @nat_table.size,
        tracked_connections: @connection_tracking.size,
        arp_entries: @arp_cache.size,
        route_types: @routes.group_by { |r| r[:type] }.transform_values(&:count)
      }
    end
    
    # Display routing table
    def show_routes
      puts "\\n" + "="*80
      puts "ROUTING TABLE"
      puts "="*80
      puts sprintf("%-18s %-15s %-15s %-10s %-6s %-8s", 
                  "Destination", "Gateway", "Genmask", "Interface", "Metric", "Type")
      puts "-"*80
      
      @routes.each do |route|
        network = int_to_ip(route[:network])
        netmask = int_to_ip(route[:netmask])
        gateway = route[:gateway] ? int_to_ip(route[:gateway]) : "*"
        
        puts sprintf("%-18s %-15s %-15s %-10s %-6d %-8s",
                    "#{network}/#{netmask_to_cidr(netmask)}",
                    gateway,
                    netmask,
                    route[:interface],
                    route[:metric],
                    route[:type])
      end
    end
    
    # Display NAT table
    def show_nat_table
      puts "\\n" + "="*80
      puts "NAT TRANSLATION TABLE"
      puts "="*80
      puts sprintf("%-25s %-25s %-8s %-10s", "Internal", "External", "Protocol", "Type")
      puts "-"*80
      
      @nat_table.each do |key, mapping|
        internal = "#{mapping[:internal_ip]}:#{mapping[:internal_port]}"
        external = "#{mapping[:external_ip]}:#{mapping[:external_port]}"
        protocol = mapping[:protocol]
        type = mapping[:type] || :dynamic
        
        puts sprintf("%-25s %-25s %-8s %-10s", internal, external, protocol, type)
      end
    end
    
    private
    
    def ip_to_int(ip_str)
      return ip_str if ip_str.is_a?(Integer)
      IPAddress.string_to_int(ip_str)
    end
    
    def int_to_ip(ip_int)
      IPAddress.int_to_string(ip_int)
    end
    
    def netmask_to_cidr(netmask)
      IPAddress.mask_to_cidr(int_to_ip(netmask))
    end
    
    def allocate_external_port(dst_port, protocol)
      # Try to use same port if available
      base_port = dst_port
      (0...1000).each do |offset|
        port = base_port + offset
        port = 49152 + offset if port > 65535
        
        key = "#{port}/#{protocol}"
        return port unless @nat_table.key?(key)
      end
      
      # Fallback to random port
      Random.rand(49152..65535)
    end
  end
  
  # LoadBalancer for distributing traffic across multiple backends
  class LoadBalancer
    ALGORITHMS = [:round_robin, :least_connections, :weighted, :ip_hash, :least_response_time]
    
    attr_reader :algorithm, :backends, :health_checks
    
    def initialize(algorithm: :round_robin)
      @algorithm = algorithm
      @backends = []
      @current_index = 0
      @connections = Hash.new(0)
      @response_times = Hash.new { |h, k| h[k] = [] }
      @health_checks = {}
      @backend_mutex = Mutex.new
    end
    
    # Add backend server
    def add_backend(ip, port, weight: 1, health_check: true, max_connections: 1000)
      backend = {
        ip: ip,
        port: port,
        weight: weight,
        healthy: true,
        connections: 0,
        max_connections: max_connections,
        total_requests: 0,
        failed_requests: 0,
        avg_response_time: 0,
        last_health_check: Time.now
      }
      
      @backend_mutex.synchronize { @backends << backend }
      start_health_check(backend) if health_check
      
      puts "Added backend: #{ip}:#{port} (weight: #{weight})"
    end
    
    # Remove backend server
    def remove_backend(ip, port)
      @backend_mutex.synchronize do
        @backends.reject! { |b| b[:ip] == ip && b[:port] == port }
      end
      puts "Removed backend: #{ip}:#{port}"
    end
    
    # Select backend based on algorithm
    def select_backend(client_ip = nil, flow_hash = nil)
      @backend_mutex.synchronize do
        healthy_backends = @backends.select { |b| b[:healthy] && b[:connections] < b[:max_connections] }
        return nil if healthy_backends.empty?
        
        case @algorithm
        when :round_robin
          backend = healthy_backends[@current_index % healthy_backends.size]
          @current_index += 1
          backend
        when :least_connections
          healthy_backends.min_by { |b| b[:connections] }
        when :weighted
          select_weighted_backend(healthy_backends)
        when :ip_hash
          return nil unless client_ip
          index = IPAddress.string_to_int(client_ip) % healthy_backends.size
          healthy_backends[index]
        when :least_response_time
          healthy_backends.min_by { |b| b[:avg_response_time] }
        else
          healthy_backends.first
        end
      end
    end
    
    # Mark backend connection as started
    def backend_connection_start(backend)
      @backend_mutex.synchronize do
        backend[:connections] += 1
        backend[:total_requests] += 1
      end
    end
    
    # Mark backend connection as finished
    def backend_connection_end(backend, response_time = nil, success = true)
      @backend_mutex.synchronize do
        backend[:connections] -= 1
        backend[:failed_requests] += 1 unless success
        
        if response_time
          @response_times[backend] << response_time
          # Keep only last 100 response times
          @response_times[backend] = @response_times[backend].last(100)
          backend[:avg_response_time] = @response_times[backend].sum.to_f / @response_times[backend].size
        end
      end
    end
    
    # Get load balancer statistics
    def get_stats
      @backend_mutex.synchronize do
        {
          algorithm: @algorithm,
          total_backends: @backends.size,
          healthy_backends: @backends.count { |b| b[:healthy] },
          total_connections: @backends.sum { |b| b[:connections] },
          backends: @backends.map do |backend|
            {
              address: "#{backend[:ip]}:#{backend[:port]}",
              healthy: backend[:healthy],
              connections: backend[:connections],
              weight: backend[:weight],
              total_requests: backend[:total_requests],
              failed_requests: backend[:failed_requests],
              success_rate: calculate_success_rate(backend),
              avg_response_time: backend[:avg_response_time].round(2)
            }
          end
        }
      end
    end
    
    private
    
    def select_weighted_backend(backends)
      total_weight = backends.sum { |b| b[:weight] }
      random = Random.rand(total_weight)
      
      cumulative_weight = 0
      backends.each do |backend|
        cumulative_weight += backend[:weight]
        return backend if random < cumulative_weight
      end
      
      backends.last
    end
    
    def start_health_check(backend)
      Thread.new do
        loop do
          begin
            backend[:healthy] = perform_health_check(backend)
            backend[:last_health_check] = Time.now
          rescue => e
            backend[:healthy] = false
            puts "Health check failed for #{backend[:ip]}:#{backend[:port]}: #{e.message}"
          end
          
          sleep(30)  # Check every 30 seconds
        end
      end
    end
    
    def perform_health_check(backend)
      # Simple TCP connect test
      # In production, this could be HTTP health check, etc.
      begin
        socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
        sockaddr = Socket.sockaddr_in(backend[:port], backend[:ip])
        
        # Non-blocking connect with timeout
        begin
          socket.connect_nonblock(sockaddr)
        rescue IO::WaitWritable
          # Wait for connection with timeout
          if IO.select(nil, [socket], nil, 5)  # 5 second timeout
            begin
              socket.connect_nonblock(sockaddr)
            rescue Errno::EISCONN
              # Already connected
            rescue => e
              return false
            end
          else
            return false  # Timeout
          end
        end
        
        socket.close
        true
      rescue => e
        false
      end
    end
    
    def calculate_success_rate(backend)
      total = backend[:total_requests]
      return 100.0 if total == 0
      
      failed = backend[:failed_requests]
      ((total - failed).to_f / total * 100).round(2)
    end
  end
end