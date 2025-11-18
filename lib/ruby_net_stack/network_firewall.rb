# frozen_string_literal: true

module RubyNetStack
  # NetworkFirewall provides packet filtering, intrusion detection,
  # and DDoS protection capabilities
  class NetworkFirewall
    attr_reader :rules, :stats, :ddos_protection, :intrusion_detection
    
    def initialize
      @rules = []
      @stats = FirewallStats.new
      @ddos_protection = DDoSProtection.new
      @intrusion_detection = IntrusionDetection.new
      @rate_limiters = {}
      @connection_limits = Hash.new(0)
      @blocked_ips = Set.new
      @whitelist = Set.new
      @rule_mutex = Mutex.new
    end
    
    # Add firewall rule
    def add_rule(rule_hash)
      rule = FirewallRule.new(rule_hash)
      @rule_mutex.synchronize { @rules << rule }
      puts "Added firewall rule: #{rule}"
    end
    
    # Remove firewall rule by ID
    def remove_rule(rule_id)
      @rule_mutex.synchronize do
        @rules.reject! { |rule| rule.id == rule_id }
      end
    end
    
    # Process packet through firewall
    def filter_packet(packet, direction: :inbound, connection_id: nil)
      # Update statistics
      @stats.packet_processed(direction)
      
      # Check whitelist first
      src_ip = packet.respond_to?(:src_ip) ? packet.src_ip : nil
      dst_ip = packet.respond_to?(:dst_ip) ? packet.dst_ip : nil
      
      if src_ip && @whitelist.include?(src_ip)
        @stats.packet_allowed(:whitelist)
        return :allow
      end
      
      # Check if IP is blocked
      if src_ip && @blocked_ips.include?(src_ip)
        @stats.packet_blocked(:blacklist)
        return :deny
      end
      
      # DDoS protection
      if direction == :inbound
        ddos_result = @ddos_protection.check_packet(packet)
        if ddos_result == :deny
          @stats.packet_blocked(:ddos)
          @blocked_ips.add(src_ip) if src_ip
          return :deny
        end
      end
      
      # Intrusion detection
      ids_result = @intrusion_detection.analyze_packet(packet)
      if ids_result[:action] == :deny
        @stats.packet_blocked(:ids)
        @blocked_ips.add(src_ip) if src_ip
        return :deny
      end
      
      # Apply firewall rules
      @rule_mutex.synchronize do
        @rules.each do |rule|
          result = rule.match(packet, direction: direction)
          next if result == :no_match
          
          if result == :allow
            @stats.packet_allowed(:rule)
            @stats.rule_matched(rule.id)
            return :allow
          elsif result == :deny
            @stats.packet_blocked(:rule)
            @stats.rule_matched(rule.id)
            return :deny
          end
        end
      end
      
      # Default policy (configurable, defaulting to allow for now)
      @stats.packet_allowed(:default)
      :allow
    end
    
    # Add IP to whitelist
    def whitelist_ip(ip)
      @whitelist.add(ip)
      puts "Whitelisted IP: #{ip}"
    end
    
    # Add IP to blacklist
    def blacklist_ip(ip, duration: nil)
      @blocked_ips.add(ip)
      
      if duration
        Thread.new do
          sleep(duration)
          @blocked_ips.delete(ip)
          puts "Unblocked IP: #{ip} (duration expired)"
        end
      end
      
      puts "Blacklisted IP: #{ip}#{duration ? " for #{duration}s" : ""}"
    end
    
    # Get firewall statistics
    def get_stats
      @stats.to_hash.merge(@ddos_protection.get_stats).merge(@intrusion_detection.get_stats)
    end
    
    # Clear blocked IPs
    def clear_blocked_ips
      count = @blocked_ips.size
      @blocked_ips.clear
      puts "Cleared #{count} blocked IPs"
    end
    
    # Load rules from configuration
    def load_rules_from_config(rules_config)
      rules_config.each { |rule_hash| add_rule(rule_hash) }
    end
  end
  
  # Individual firewall rule
  class FirewallRule
    attr_reader :id, :name, :action, :direction, :protocol
    attr_reader :src_ip, :dst_ip, :src_port, :dst_port
    attr_reader :enabled, :log, :created_at, :priority
    
    def initialize(options = {})
      @id = options[:id] || SecureRandom.uuid
      @name = options[:name] || "Rule #{@id[0..7]}"
      @action = options[:action] || :allow  # :allow, :deny, :reject
      @direction = options[:direction] || :any  # :inbound, :outbound, :any
      @protocol = options[:protocol] || :any  # :tcp, :udp, :icmp, :any
      @src_ip = parse_ip_range(options[:src_ip] || "0.0.0.0/0")
      @dst_ip = parse_ip_range(options[:dst_ip] || "0.0.0.0/0")
      @src_port = parse_port_range(options[:src_port])
      @dst_port = parse_port_range(options[:dst_port])
      @enabled = options[:enabled] != false
      @log = options[:log] || false
      @priority = options[:priority] || 100
      @created_at = Time.now
    end
    
    # Check if packet matches this rule
    def match(packet, direction: :inbound)
      return :no_match unless @enabled
      return :no_match if @direction != :any && @direction != direction
      
      # Protocol matching
      case @protocol
      when :tcp
        return :no_match unless packet.is_a?(TCPSegment)
      when :udp
        return :no_match unless packet.is_a?(UDPDatagram)
      when :icmp
        return :no_match unless packet.is_a?(ICMPPacket)
      end
      
      # IP address matching
      if packet.respond_to?(:src_ip)
        return :no_match unless ip_matches?(@src_ip, packet.src_ip)
      end
      
      if packet.respond_to?(:dst_ip)
        return :no_match unless ip_matches?(@dst_ip, packet.dst_ip)
      end
      
      # Port matching
      if packet.respond_to?(:src_port) && @src_port
        return :no_match unless port_matches?(@src_port, packet.src_port)
      end
      
      if packet.respond_to?(:dst_port) && @dst_port
        return :no_match unless port_matches?(@dst_port, packet.dst_port)
      end
      
      # Log if required
      if @log
        puts "Firewall rule matched: #{@name} (#{@action}) - #{packet.class}"
      end
      
      @action
    end
    
    def to_s
      "#{@name}: #{@action.upcase} #{@direction} #{@protocol} " +
      "#{@src_ip || 'any'}:#{@src_port || 'any'} -> #{@dst_ip || 'any'}:#{@dst_port || 'any'}"
    end
    
    private
    
    def parse_ip_range(ip_str)
      return nil if ip_str.nil? || ip_str == "any"
      
      if ip_str.include?("/")
        # CIDR notation
        network, prefix_len = ip_str.split("/")
        {
          type: :cidr,
          network: IPAddress.string_to_int(network),
          prefix_length: prefix_len.to_i
        }
      elsif ip_str.include?("-")
        # Range notation (e.g., 192.168.1.1-192.168.1.100)
        start_ip, end_ip = ip_str.split("-")
        {
          type: :range,
          start: IPAddress.string_to_int(start_ip.strip),
          end: IPAddress.string_to_int(end_ip.strip)
        }
      else
        # Single IP
        {
          type: :single,
          ip: IPAddress.string_to_int(ip_str)
        }
      end
    end
    
    def parse_port_range(port_str)
      return nil if port_str.nil? || port_str == "any"
      
      if port_str.include?("-")
        # Port range
        start_port, end_port = port_str.split("-")
        {
          type: :range,
          start: start_port.to_i,
          end: end_port.to_i
        }
      else
        # Single port
        {
          type: :single,
          port: port_str.to_i
        }
      end
    end
    
    def ip_matches?(rule_ip, packet_ip)
      return true if rule_ip.nil?
      
      packet_ip_int = IPAddress.string_to_int(packet_ip)
      
      case rule_ip[:type]
      when :single
        rule_ip[:ip] == packet_ip_int
      when :range
        packet_ip_int >= rule_ip[:start] && packet_ip_int <= rule_ip[:end]
      when :cidr
        network = rule_ip[:network]
        prefix_len = rule_ip[:prefix_length]
        netmask = (0xffffffff << (32 - prefix_len)) & 0xffffffff
        (packet_ip_int & netmask) == network
      else
        false
      end
    end
    
    def port_matches?(rule_port, packet_port)
      return true if rule_port.nil?
      
      case rule_port[:type]
      when :single
        rule_port[:port] == packet_port
      when :range
        packet_port >= rule_port[:start] && packet_port <= rule_port[:end]
      else
        false
      end
    end
  end
  
  # DDoS Protection system
  class DDoSProtection
    def initialize
      @connection_rates = Hash.new { |h, k| h[k] = RateLimit.new(100, 60) }  # 100 connections per minute
      @packet_rates = Hash.new { |h, k| h[k] = RateLimit.new(1000, 60) }    # 1000 packets per minute
      @bandwidth_rates = Hash.new { |h, k| h[k] = RateLimit.new(10_000_000, 60) }  # 10MB per minute
      @attack_patterns = AttackPatternDetector.new
      @stats = {
        connections_blocked: 0,
        packets_blocked: 0,
        bandwidth_blocked: 0,
        attacks_detected: 0
      }
    end
    
    def check_packet(packet)
      src_ip = packet.respond_to?(:src_ip) ? packet.src_ip : "unknown"
      
      # Check packet rate
      packet_size = packet.respond_to?(:total_length) ? packet.total_length : 64
      
      unless @packet_rates[src_ip].allow?
        @stats[:packets_blocked] += 1
        return :deny
      end
      
      unless @bandwidth_rates[src_ip].allow?(packet_size)
        @stats[:bandwidth_blocked] += 1
        return :deny
      end
      
      # Check for attack patterns
      if @attack_patterns.analyze(packet) == :attack
        @stats[:attacks_detected] += 1
        return :deny
      end
      
      :allow
    end
    
    def connection_attempt(src_ip)
      unless @connection_rates[src_ip].allow?
        @stats[:connections_blocked] += 1
        return :deny
      end
      
      :allow
    end
    
    def get_stats
      {
        ddos_protection: @stats.dup
      }
    end
  end
  
  # Intrusion Detection System
  class IntrusionDetection
    def initialize
      @signatures = load_signatures
      @anomaly_detector = AnomalyDetector.new
      @stats = {
        signatures_matched: 0,
        anomalies_detected: 0,
        threats_blocked: 0
      }
    end
    
    def analyze_packet(packet)
      # Signature-based detection
      signature_result = check_signatures(packet)
      if signature_result[:match]
        @stats[:signatures_matched] += 1
        return { action: :deny, reason: "Signature: #{signature_result[:signature]}" }
      end
      
      # Anomaly detection
      if @anomaly_detector.is_anomalous?(packet)
        @stats[:anomalies_detected] += 1
        return { action: :deny, reason: "Anomalous behavior detected" }
      end
      
      { action: :allow, reason: "Clean" }
    end
    
    def get_stats
      {
        intrusion_detection: @stats.dup
      }
    end
    
    private
    
    def load_signatures
      [
        # Common attack patterns
        {
          name: "Port Scan",
          pattern: ->(packet) { 
            packet.is_a?(TCPSegment) && packet.syn? && !packet.ack?
          }
        },
        {
          name: "SYN Flood",
          pattern: ->(packet) {
            packet.is_a?(TCPSegment) && packet.syn? && !packet.ack?
          }
        },
        {
          name: "Ping of Death",
          pattern: ->(packet) {
            packet.is_a?(ICMPPacket) && packet.total_length > 65535
          }
        }
      ]
    end
    
    def check_signatures(packet)
      @signatures.each do |sig|
        if sig[:pattern].call(packet)
          return { match: true, signature: sig[:name] }
        end
      end
      
      { match: false }
    end
  end
  
  # Firewall statistics tracker
  class FirewallStats
    def initialize
      @stats = {
        total_packets: 0,
        inbound_packets: 0,
        outbound_packets: 0,
        allowed_packets: 0,
        blocked_packets: 0,
        allowed_reasons: Hash.new(0),
        blocked_reasons: Hash.new(0),
        rule_matches: Hash.new(0),
        start_time: Time.now
      }
      @mutex = Mutex.new
    end
    
    def packet_processed(direction)
      @mutex.synchronize do
        @stats[:total_packets] += 1
        @stats[:"#{direction}_packets"] += 1
      end
    end
    
    def packet_allowed(reason)
      @mutex.synchronize do
        @stats[:allowed_packets] += 1
        @stats[:allowed_reasons][reason] += 1
      end
    end
    
    def packet_blocked(reason)
      @mutex.synchronize do
        @stats[:blocked_packets] += 1
        @stats[:blocked_reasons][reason] += 1
      end
    end
    
    def rule_matched(rule_id)
      @mutex.synchronize do
        @stats[:rule_matches][rule_id] += 1
      end
    end
    
    def to_hash
      @mutex.synchronize do
        uptime = Time.now - @stats[:start_time]
        
        @stats.merge({
          uptime_seconds: uptime.round,
          packets_per_second: (@stats[:total_packets] / uptime).round(2),
          block_rate: ((@stats[:blocked_packets].to_f / @stats[:total_packets]) * 100).round(2)
        })
      end
    end
  end
  
  # Rate limiting utility
  class RateLimit
    def initialize(limit, window_seconds)
      @limit = limit
      @window = window_seconds
      @requests = []
      @mutex = Mutex.new
    end
    
    def allow?(cost = 1)
      @mutex.synchronize do
        now = Time.now
        # Remove old requests outside window
        @requests.reject! { |time| (now - time) > @window }
        
        # Check if adding this request would exceed limit
        current_usage = @requests.sum { |time| time.is_a?(Hash) ? time[:cost] : 1 }
        return false if (current_usage + cost) > @limit
        
        # Record this request
        @requests << { time: now, cost: cost }
        true
      end
    end
  end
  
  # Attack pattern detection
  class AttackPatternDetector
    def initialize
      @recent_packets = []
      @mutex = Mutex.new
    end
    
    def analyze(packet)
      @mutex.synchronize do
        @recent_packets << {
          packet: packet,
          time: Time.now,
          src_ip: packet.respond_to?(:src_ip) ? packet.src_ip : nil,
          dst_port: packet.respond_to?(:dst_port) ? packet.dst_port : nil
        }
        
        # Keep only last 1000 packets
        @recent_packets = @recent_packets.last(1000)
        
        # Detect port scanning
        return :attack if port_scan_detected?
        
        # Detect SYN flood
        return :attack if syn_flood_detected?
        
        :normal
      end
    end
    
    private
    
    def port_scan_detected?
      # Look for many different destination ports from same source in short time
      recent = @recent_packets.select { |p| (Time.now - p[:time]) < 60 }  # Last minute
      
      recent.group_by { |p| p[:src_ip] }.any? do |src_ip, packets|
        next false if src_ip.nil?
        
        unique_ports = packets.map { |p| p[:dst_port] }.compact.uniq
        unique_ports.size > 10  # More than 10 different ports
      end
    end
    
    def syn_flood_detected?
      # Look for many SYN packets from same source
      recent = @recent_packets.select { |p| (Time.now - p[:time]) < 10 }  # Last 10 seconds
      
      recent.group_by { |p| p[:src_ip] }.any? do |src_ip, packets|
        next false if src_ip.nil?
        
        syn_packets = packets.count do |p|
          p[:packet].is_a?(TCPSegment) && p[:packet].syn? && !p[:packet].ack?
        end
        
        syn_packets > 50  # More than 50 SYN packets in 10 seconds
      end
    end
  end
  
  # Anomaly detection using simple statistical methods
  class AnomalyDetector
    def initialize
      @baselines = {
        packet_sizes: StatisticalBaseline.new,
        packet_rates: StatisticalBaseline.new,
        connection_patterns: {}
      }
    end
    
    def is_anomalous?(packet)
      # Check packet size anomaly
      packet_size = packet.respond_to?(:total_length) ? packet.total_length : 64
      return true if @baselines[:packet_sizes].is_anomalous?(packet_size)
      
      # Add more sophisticated anomaly detection as needed
      false
    end
  end
  
  # Statistical baseline for anomaly detection
  class StatisticalBaseline
    def initialize(window_size: 1000, threshold: 3.0)
      @window_size = window_size
      @threshold = threshold  # Standard deviations
      @values = []
      @mutex = Mutex.new
    end
    
    def add_value(value)
      @mutex.synchronize do
        @values << value
        @values = @values.last(@window_size)
      end
    end
    
    def is_anomalous?(value)
      @mutex.synchronize do
        add_value(value)
        
        return false if @values.size < 30  # Need minimum samples
        
        mean = @values.sum.to_f / @values.size
        variance = @values.map { |v| (v - mean) ** 2 }.sum / @values.size
        std_dev = Math.sqrt(variance)
        
        return false if std_dev == 0
        
        z_score = (value - mean).abs / std_dev
        z_score > @threshold
      end
    end
  end
end