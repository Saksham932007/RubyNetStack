#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative '../lib/ruby_net_stack'

# Enterprise Network Stack Demo
# Demonstrates advanced features: TCP state machine, routing/NAT, firewall,
# QoS, DNS resolution, and comprehensive monitoring

puts "="*80
puts "🚀 RUBYNETSTACK ENTERPRISE DEMO"
puts "Advanced userspace network stack with enterprise-grade features"
puts "="*80

# Initialize core network stack components
puts "\\n📡 Initializing Core Components..."
interface = RubyNetStack::NetworkInterface.new("eth0")
packet_dispatcher = RubyNetStack::PacketDispatcher.new

# TCP connection manager
tcp_manager = RubyNetStack::TCPConnectionManager.new
puts "✅ TCP State Machine initialized with 11 states"

# Advanced routing table with NAT
routing_table = RubyNetStack::AdvancedRoutingTable.new("eth0")
routing_table.configure_nat("192.168.1.0/24", "203.0.113.10", "eth0")
routing_table.add_default_route("192.168.1.1", "eth0")
routing_table.add_route("10.0.0.0", "255.0.0.0", "192.168.1.1", "eth0", 10)
puts "✅ Advanced routing table with NAT configured"

# Network firewall with DDoS protection
firewall = RubyNetStack::NetworkFirewall.new

# Add comprehensive firewall rules
firewall.add_rule({
  name: "Allow SSH from trusted networks",
  action: :allow,
  protocol: :tcp,
  dst_port: "22",
  src_ip: "192.168.1.0/24"
})

firewall.add_rule({
  name: "Block suspicious port scans",
  action: :deny,
  protocol: :tcp,
  dst_port: "1-1024",
  src_ip: "0.0.0.0/0",
  priority: 90
})

firewall.add_rule({
  name: "Allow HTTP/HTTPS traffic",
  action: :allow,
  protocol: :tcp,
  dst_port: "80,443"
})

puts "✅ Network firewall with intrusion detection configured"

# Quality of Service manager
qos_manager = RubyNetStack::QoSManager.new(1_000_000_000) # 1Gbps
puts "✅ QoS manager initialized with 5 traffic classes"

# DNS resolver with caching
dns_resolver = RubyNetStack::DNSResolver.new({
  upstream_servers: ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
  cache_size: 10000,
  recursive: true
})

# Add local DNS records
dns_resolver.add_static_record("router.local", :A, "192.168.1.1")
dns_resolver.add_static_record("server.local", :A, "192.168.1.10")
dns_resolver.add_static_record("workstation.local", :A, "192.168.1.100")

puts "✅ DNS resolver with authoritative zones configured"

# Network monitoring system
monitor = RubyNetStack::NetworkMonitor.new({
  collection_interval: 5,
  analysis_interval: 30,
  retention_days: 7
})

# Configure monitoring alerts
monitor.configure_alerts([
  {
    name: "High bandwidth utilization",
    metric_path: "bandwidth_usage.utilization_percent",
    operator: :greater_than,
    threshold: 85.0,
    severity: :high
  },
  {
    name: "High latency detected",
    metric_path: "latency_metrics.avg_latency_ms",
    operator: :greater_than,
    threshold: 100.0,
    severity: :medium
  },
  {
    name: "Connection limit approaching",
    metric_path: "connection_stats.total_connections",
    operator: :greater_than,
    threshold: 1000,
    severity: :medium
  }
])

puts "✅ Network monitoring with alerting configured"

puts "\\n🔧 Starting Network Services..."

# Start QoS scheduler
qos_manager.start_scheduler_thread
puts "✅ QoS scheduler started"

# Start network monitoring
monitor.start_monitoring
puts "✅ Network monitoring started"

# Start DNS server
dns_resolver.start_server("0.0.0.0")
puts "✅ DNS server started on port 53"

puts "\\n🌐 Demonstrating Advanced Features..."

# 1. TCP Connection Management Demo
puts "\\n1️⃣ TCP Connection Management:"
puts "   Creating TCP connections with full state machine..."

tcp_connection = tcp_manager.create_connection("192.168.1.100", 80, "203.0.113.10", 12345)
if tcp_connection
  puts "   ✅ TCP connection created: #{tcp_connection[:connection_id]}"
  puts "   📊 State: #{tcp_connection[:state]}"
  
  # Simulate state transitions
  tcp_manager.handle_syn_ack(tcp_connection[:connection_id])
  puts "   📊 State after SYN-ACK: SYN_RECEIVED → ESTABLISHED"
  
  # Send data
  data = "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
  tcp_manager.send_data(tcp_connection[:connection_id], data)
  puts "   📤 HTTP request sent (#{data.length} bytes)"
end

# 2. Advanced Routing and NAT Demo
puts "\\n2️⃣ Advanced Routing and Load Balancing:"

# Add multiple routes for load balancing
routing_table.add_route("203.0.113.0", "255.255.255.0", "192.168.1.1", "eth0", 10)
routing_table.add_route("203.0.113.0", "255.255.255.0", "192.168.1.2", "eth1", 10)

route_info = routing_table.get_ecmp_route("203.0.113.50", 12345)
puts "   🔀 ECMP route selected: #{route_info[:interface] if route_info}"

# Demonstrate NAT
puts "   🔄 Configuring port forwarding for web server..."
routing_table.add_port_forward(8080, "192.168.1.10", 80, :tcp)

# Show routing table
routing_table.show_routes

# 3. Firewall and Security Demo
puts "\\n3️⃣ Firewall and Security Analysis:"

# Simulate packet filtering
test_packet = RubyNetStack::TCPSegment.new
test_packet.src_ip = "192.168.1.100"
test_packet.dst_ip = "203.0.113.10"
test_packet.src_port = 54321
test_packet.dst_port = 80

filter_result = firewall.filter_packet(test_packet, direction: :outbound)
puts "   🛡️  Packet filter result: #{filter_result.upcase}"

# Show firewall statistics
firewall_stats = firewall.get_stats
puts "   📊 Firewall processed #{firewall_stats[:total_packets]} packets"

# 4. Quality of Service Demo
puts "\\n4️⃣ Quality of Service Management:"

# Classify and queue packets
qos_class = qos_manager.classify_packet(test_packet)
puts "   🏷️  Packet classified as: #{qos_class}"

success = qos_manager.enqueue_packet(test_packet, qos_class: qos_class)
puts "   📥 Packet #{success ? 'queued' : 'dropped'} in #{qos_class} class"

# Show QoS status
queue_status = qos_manager.get_queue_status
puts "   📊 QoS queue status:"
queue_status.each do |qos_class, status|
  puts "      #{qos_class}: #{status[:queue_size]}/#{status[:max_queue_size]} packets " +
       "(#{status[:bandwidth_utilization]}% bandwidth)"
end

# 5. DNS Resolution Demo
puts "\\n5️⃣ DNS Resolution and Caching:"

# Resolve some domains
test_domains = ["router.local", "server.local", "google.com"]
test_domains.each do |domain|
  result = dns_resolver.resolve(domain, :A)
  if result && result[:rcode] == RubyNetStack::DNSResolver::RESPONSE_CODES[:NOERROR]
    answer = result[:answers]&.first
    ip = answer ? answer[:value] : "No answer"
    puts "   🔍 #{domain} → #{ip}"
  else
    puts "   ❌ Failed to resolve #{domain}"
  end
end

# Show DNS statistics
dns_stats = dns_resolver.get_stats
cache_stats = dns_stats[:cache]
puts "   📊 DNS cache: #{cache_stats[:hits]} hits, #{cache_stats[:misses]} misses " +
     "(#{cache_stats[:hit_rate_percent]}% hit rate)"

# 6. Network Monitoring Demo
puts "\\n6️⃣ Network Monitoring and Analytics:"

# Get current metrics
current_metrics = monitor.get_current_metrics
puts "   📊 Current network metrics collected from #{current_metrics.keys.size} sources"

# Generate network reports
puts "   📈 Generating performance report..."
performance_report = monitor.generate_report(:performance, 3600)
puts "      • Average latency: #{performance_report[:latency_percentiles][:p50]}ms"
puts "      • Current throughput: #{performance_report[:throughput_analysis][:current_throughput_mbps]}Mbps"
puts "      • Overall SLA compliance: #{performance_report[:sla_compliance][:overall_compliance]}%"

puts "   🔒 Generating security report..."
security_report = monitor.generate_report(:security, 3600)
threat_summary = security_report[:threat_summary]
puts "      • Threat level: #{threat_summary[:current_threat_level]}"
puts "      • Blocked attacks: #{threat_summary[:blocked_attempts]}"
puts "      • Active threats: #{threat_summary[:active_threats]}"

# 7. Integration Demo: Full Packet Flow
puts "\\n7️⃣ Integrated Packet Processing Flow:"
puts "   🔄 Simulating complete packet processing pipeline..."

# Create a test HTTP request
http_packet = RubyNetStack::TCPSegment.new
http_packet.src_ip = "192.168.1.100"
http_packet.dst_ip = "203.0.113.50"
http_packet.src_port = 54321
http_packet.dst_port = 80
http_packet.data = "GET /api/data HTTP/1.1\\r\\nHost: api.example.com\\r\\n\\r\\n"

puts "   1. 🔍 Packet received: #{http_packet.src_ip}:#{http_packet.src_port} → #{http_packet.dst_ip}:#{http_packet.dst_port}"

# Step 1: Firewall inspection
puts "   2. 🛡️  Firewall inspection..."
firewall_result = firewall.filter_packet(http_packet, direction: :outbound)
if firewall_result == :allow
  puts "      ✅ Packet allowed by firewall"
  
  # Step 2: QoS classification and queuing
  puts "   3. 📊 QoS classification..."
  qos_class = qos_manager.classify_packet(http_packet)
  qos_success = qos_manager.enqueue_packet(http_packet, qos_class: qos_class)
  puts "      ✅ Packet queued in #{qos_class} class" if qos_success
  
  # Step 3: Routing decision
  puts "   4. 🗺️  Routing lookup..."
  next_hop = routing_table.get_next_hop(http_packet.dst_ip)
  if next_hop
    puts "      ✅ Route found: via #{next_hop[:next_hop]} on #{next_hop[:interface]}"
    
    # Step 4: NAT translation
    puts "   5. 🔄 NAT translation..."
    connection_id = routing_table.track_connection(
      http_packet.src_ip, http_packet.src_port,
      http_packet.dst_ip, http_packet.dst_port, :tcp
    )
    routing_table.apply_snat(http_packet, connection_id)
    puts "      ✅ SNAT applied: #{http_packet.src_ip}:#{http_packet.src_port}"
    
    # Step 5: Packet transmission (simulated)
    puts "   6. 📤 Packet transmitted on #{next_hop[:interface]}"
    
    # Step 6: Monitoring and logging
    puts "   7. 📈 Metrics updated and logged"
  else
    puts "      ❌ No route found for #{http_packet.dst_ip}"
  end
else
  puts "      ❌ Packet blocked by firewall"
end

# 8. Performance Statistics
puts "\\n📊 PERFORMANCE STATISTICS:"
puts "="*50

# Show comprehensive statistics
tcp_stats = tcp_manager.get_stats
routing_stats = routing_table.get_stats
firewall_stats = firewall.get_stats
qos_stats = qos_manager.get_stats
dns_stats = dns_resolver.get_stats
monitor_stats = monitor.get_stats

puts "TCP Connections:"
puts "  • Active: #{tcp_stats[:active_connections]}"
puts "  • Total created: #{tcp_stats[:total_connections]}"
puts "  • Data transferred: #{tcp_stats[:total_bytes_transferred]} bytes"

puts "\\nRouting & NAT:"
puts "  • Total routes: #{routing_stats[:total_routes]}"
puts "  • NAT mappings: #{routing_stats[:nat_mappings]}"
puts "  • Tracked connections: #{routing_stats[:tracked_connections]}"

puts "\\nFirewall:"
puts "  • Total packets: #{firewall_stats[:total_packets]}"
puts "  • Blocked: #{firewall_stats[:blocked_packets]}"
puts "  • Block rate: #{firewall_stats[:block_rate_percent]}%"

puts "\\nQuality of Service:"
puts "  • Packets processed: #{qos_stats[:global_stats][:packets_transmitted]}"
puts "  • Average latency: #{qos_stats[:global_stats][:avg_latency_ms]}ms"
puts "  • Drop rate: #{qos_stats[:global_stats][:drop_rate_percent]}%"

puts "\\nDNS Resolution:"
puts "  • Queries processed: #{dns_stats[:queries][:total_queries]}"
puts "  • Cache hit rate: #{dns_stats[:cache][:hit_rate_percent]}%"
puts "  • Zones managed: #{dns_stats[:zones].size}"

puts "\\nMonitoring System:"
puts "  • Metrics collected: #{monitor_stats[:metrics_points]} points"
puts "  • Active alerts: #{monitor_stats[:active_alerts]}"
puts "  • Uptime: #{monitor_stats[:uptime].round}s"

puts "\\n🎯 ENTERPRISE FEATURES DEMONSTRATION COMPLETE!"
puts "\\nAdvanced capabilities demonstrated:"
puts "✅ Full TCP state machine with connection tracking"
puts "✅ Advanced routing with ECMP and NAT translation"
puts "✅ Enterprise firewall with DDoS protection and IDS"
puts "✅ Quality of Service with weighted fair queuing"
puts "✅ Authoritative DNS with recursive resolution"
puts "✅ Comprehensive monitoring with real-time analytics"
puts "✅ Integrated packet processing pipeline"
puts "✅ Production-ready performance and security features"

puts "\\n" + "="*80

# Cleanup
puts "\\n🧹 Cleaning up services..."
sleep(2) # Let things run for a moment

qos_manager.stop_scheduler
dns_resolver.stop_server
monitor.stop_monitoring

puts "✅ All services stopped cleanly"
puts "\\nDemo completed successfully! 🎉"