# frozen_string_literal: true

module RubyNetStack
  # QoSManager implements sophisticated traffic management with multiple
  # scheduling algorithms, bandwidth control, and priority handling
  class QoSManager
    attr_reader :schedulers, :traffic_shapers, :stats, :classes
    
    # QoS class definitions
    QOS_CLASSES = {
      interactive: { priority: 7, bandwidth_percent: 30, max_latency_ms: 50 },
      voice: { priority: 6, bandwidth_percent: 20, max_latency_ms: 20 },
      video: { priority: 5, bandwidth_percent: 25, max_latency_ms: 100 },
      bulk: { priority: 2, bandwidth_percent: 15, max_latency_ms: 1000 },
      background: { priority: 1, bandwidth_percent: 10, max_latency_ms: 5000 }
    }
    
    def initialize(total_bandwidth_bps = 1_000_000_000) # 1Gbps default
      @total_bandwidth = total_bandwidth_bps
      @classes = {}
      @schedulers = {}
      @traffic_shapers = {}
      @stats = QoSStats.new
      @packet_queue = PacketQueue.new
      @active = false
      @qos_mutex = Mutex.new
      
      initialize_default_classes
      start_scheduler_thread
    end
    
    # Initialize default QoS classes
    def initialize_default_classes
      QOS_CLASSES.each do |name, config|
        add_qos_class(name, config)
      end
    end
    
    # Add custom QoS class
    def add_qos_class(name, config)
      bandwidth_bps = (@total_bandwidth * config[:bandwidth_percent] / 100).to_i
      
      qos_class = {
        name: name,
        priority: config[:priority],
        bandwidth_bps: bandwidth_bps,
        max_latency_ms: config[:max_latency_ms],
        queue: PriorityQueue.new,
        shaper: TokenBucket.new(bandwidth_bps, bandwidth_bps / 10), # burst = 10% of rate
        stats: ClassStats.new(name),
        active: true
      }
      
      @qos_mutex.synchronize do
        @classes[name] = qos_class
        @schedulers[name] = WeightedFairScheduler.new(config[:priority])
        @traffic_shapers[name] = TrafficShaper.new(bandwidth_bps)
      end
      
      puts "Added QoS class: #{name} (priority: #{config[:priority]}, bandwidth: #{bandwidth_bps/1000}kbps)"
    end
    
    # Remove QoS class
    def remove_qos_class(name)
      return if QOS_CLASSES.key?(name)  # Cannot remove default classes
      
      @qos_mutex.synchronize do
        @classes.delete(name)
        @schedulers.delete(name)
        @traffic_shapers.delete(name)
      end
    end
    
    # Classify packet into QoS class
    def classify_packet(packet)
      # Default classification logic
      case packet
      when TCPSegment
        return classify_tcp_packet(packet)
      when UDPDatagram
        return classify_udp_packet(packet)
      when ICMPPacket
        return :interactive  # ICMP is typically interactive
      else
        return :background   # Unknown packets go to background
      end
    end
    
    # Enqueue packet with QoS classification
    def enqueue_packet(packet, qos_class: nil)
      qos_class ||= classify_packet(packet)
      
      # Ensure QoS class exists
      unless @classes.key?(qos_class)
        qos_class = :background
      end
      
      packet_wrapper = QoSPacket.new(packet, qos_class, Time.now)
      
      @qos_mutex.synchronize do
        class_info = @classes[qos_class]
        
        # Check if traffic shaper allows this packet
        unless class_info[:shaper].consume(packet_wrapper.size)
          @stats.packet_dropped(qos_class, :rate_limit)
          return false
        end
        
        # Check queue capacity
        if class_info[:queue].size >= class_info[:queue].max_size
          @stats.packet_dropped(qos_class, :queue_full)
          return false
        end
        
        # Enqueue packet
        class_info[:queue].enqueue(packet_wrapper)
        @stats.packet_enqueued(qos_class)
        
        true
      end
    end
    
    # Dequeue next packet based on scheduling algorithm
    def dequeue_packet
      @qos_mutex.synchronize do
        # Find highest priority non-empty queue
        sorted_classes = @classes.values.sort_by { |cls| -cls[:priority] }
        
        sorted_classes.each do |class_info|
          next if class_info[:queue].empty?
          
          # Check bandwidth allocation
          if class_info[:shaper].tokens_available? > 0
            packet_wrapper = class_info[:queue].dequeue
            
            # Calculate queuing delay
            queuing_delay = (Time.now - packet_wrapper.enqueue_time) * 1000  # ms
            @stats.packet_dequeued(class_info[:name], queuing_delay)
            
            # Check latency SLA
            if queuing_delay > class_info[:max_latency_ms]
              @stats.sla_violation(class_info[:name])
            end
            
            return packet_wrapper
          end
        end
        
        nil  # No packets available
      end
    end
    
    # Get all queued packets (for monitoring)
    def get_queue_status
      @qos_mutex.synchronize do
        @classes.transform_values do |class_info|
          {
            queue_size: class_info[:queue].size,
            max_queue_size: class_info[:queue].max_size,
            tokens_available: class_info[:shaper].tokens_available?,
            bandwidth_utilization: class_info[:shaper].utilization_percent,
            priority: class_info[:priority]
          }
        end
      end
    end
    
    # Start the packet scheduler thread
    def start_scheduler_thread
      return if @active
      
      @active = true
      @scheduler_thread = Thread.new do
        while @active
          begin
            # Process packets based on scheduling algorithm
            process_scheduler_cycle
            sleep(0.001)  # 1ms scheduling cycle
          rescue => e
            puts "QoS Scheduler error: #{e.message}"
          end
        end
      end
      
      puts "QoS Scheduler started"
    end
    
    # Stop the scheduler thread
    def stop_scheduler
      @active = false
      @scheduler_thread&.join
      puts "QoS Scheduler stopped"
    end
    
    # Get comprehensive QoS statistics
    def get_stats
      @qos_mutex.synchronize do
        {
          total_bandwidth_bps: @total_bandwidth,
          classes: @classes.transform_values { |cls| cls[:stats].to_hash },
          global_stats: @stats.to_hash,
          queue_status: get_queue_status
        }
      end
    end
    
    # Configure bandwidth limits
    def set_bandwidth_limit(qos_class, bandwidth_bps)
      @qos_mutex.synchronize do
        return unless @classes.key?(qos_class)
        
        @classes[qos_class][:bandwidth_bps] = bandwidth_bps
        @classes[qos_class][:shaper] = TokenBucket.new(bandwidth_bps, bandwidth_bps / 10)
        
        puts "Updated bandwidth for #{qos_class}: #{bandwidth_bps/1000}kbps"
      end
    end
    
    # Add traffic shaping rule
    def add_shaping_rule(pattern, qos_class)
      # Traffic shaping rules for automatic classification
      # This would be expanded with more sophisticated pattern matching
      puts "Added shaping rule: #{pattern} -> #{qos_class}"
    end
    
    private
    
    def classify_tcp_packet(packet)
      # Classify based on ports and flags
      case packet.dst_port
      when 22        # SSH
        :interactive
      when 80, 443   # HTTP/HTTPS
        :interactive
      when 25, 587   # SMTP
        :bulk
      when 21        # FTP
        :bulk
      when 53        # DNS
        :interactive
      else
        # Check if interactive (small packets, ACK-only)
        if packet.data&.length.to_i < 100 && packet.ack? && !packet.syn?
          :interactive
        else
          :background
        end
      end
    end
    
    def classify_udp_packet(packet)
      case packet.dst_port
      when 53        # DNS
        :interactive
      when 123       # NTP
        :interactive
      when 67, 68    # DHCP
        :interactive
      when 5060..5080 # SIP (VoIP signaling)
        :voice
      when 10000..20000 # RTP (VoIP media)
        :voice
      when 1024..49151  # Dynamic ports - could be anything
        packet.data&.length.to_i < 500 ? :interactive : :background
      else
        :background
      end
    end
    
    def process_scheduler_cycle
      # Weighted Fair Queuing implementation
      @qos_mutex.synchronize do
        total_weight = @classes.values.sum { |cls| cls[:priority] }
        return if total_weight == 0
        
        @classes.each do |name, class_info|
          next if class_info[:queue].empty?
          
          # Calculate quantum (how many bytes this class can send)
          weight_ratio = class_info[:priority].to_f / total_weight
          quantum = (@total_bandwidth / 8 * 0.001 * weight_ratio).to_i  # bytes per ms
          
          bytes_sent = 0
          while bytes_sent < quantum && !class_info[:queue].empty?
            packet_wrapper = class_info[:queue].dequeue
            break unless packet_wrapper
            
            bytes_sent += packet_wrapper.size
            @stats.packet_transmitted(name, packet_wrapper.size)
            
            # In a real implementation, this would send the packet
            # For now, we just simulate the transmission
          end
        end
      end
    end
  end
  
  # QoS packet wrapper with metadata
  class QoSPacket
    attr_reader :packet, :qos_class, :enqueue_time, :size, :priority
    
    def initialize(packet, qos_class, enqueue_time)
      @packet = packet
      @qos_class = qos_class
      @enqueue_time = enqueue_time
      @size = calculate_packet_size(packet)
      @priority = QoSManager::QOS_CLASSES[qos_class]&.[](:priority) || 0
    end
    
    private
    
    def calculate_packet_size(packet)
      case packet
      when TCPSegment, UDPDatagram
        # Header + data size
        base_size = packet.respond_to?(:header_length) ? packet.header_length : 20
        data_size = packet.respond_to?(:data) && packet.data ? packet.data.length : 0
        base_size + data_size
      else
        64  # Default size
      end
    end
  end
  
  # Priority queue implementation
  class PriorityQueue
    attr_reader :size, :max_size
    
    def initialize(max_size = 1000)
      @queue = []
      @max_size = max_size
      @mutex = Mutex.new
    end
    
    def enqueue(packet_wrapper)
      @mutex.synchronize do
        return false if @queue.size >= @max_size
        
        # Insert packet in priority order
        insert_index = @queue.bsearch_index { |p| p.priority <= packet_wrapper.priority } || @queue.size
        @queue.insert(insert_index, packet_wrapper)
        true
      end
    end
    
    def dequeue
      @mutex.synchronize do
        @queue.shift
      end
    end
    
    def empty?
      @queue.empty?
    end
    
    def size
      @queue.size
    end
    
    def peek
      @queue.first
    end
  end
  
  # Token bucket for traffic shaping
  class TokenBucket
    attr_reader :rate, :burst_size
    
    def initialize(rate_bps, burst_size)
      @rate = rate_bps        # bits per second
      @burst_size = burst_size # burst size in bits
      @tokens = burst_size.to_f
      @last_update = Time.now
      @mutex = Mutex.new
    end
    
    # Check if tokens are available
    def tokens_available?
      @mutex.synchronize do
        update_tokens
        @tokens > 0
      end
    end
    
    # Consume tokens for packet transmission
    def consume(bytes)
      bits = bytes * 8
      
      @mutex.synchronize do
        update_tokens
        
        if @tokens >= bits
          @tokens -= bits
          true
        else
          false
        end
      end
    end
    
    # Get current utilization percentage
    def utilization_percent
      @mutex.synchronize do
        update_tokens
        (((@burst_size - @tokens) / @burst_size) * 100).round(2)
      end
    end
    
    private
    
    def update_tokens
      now = Time.now
      time_passed = now - @last_update
      
      # Add tokens based on rate and time passed
      tokens_to_add = @rate * time_passed
      @tokens = [@tokens + tokens_to_add, @burst_size].min
      @last_update = now
    end
  end
  
  # Weighted Fair Scheduler
  class WeightedFairScheduler
    attr_reader :weight, :virtual_time, :packets_sent
    
    def initialize(weight)
      @weight = weight
      @virtual_time = 0.0
      @packets_sent = 0
      @last_service_time = Time.now
    end
    
    def schedule_packet(packet_size)
      # Update virtual time based on packet size and weight
      @virtual_time += packet_size.to_f / @weight
      @packets_sent += 1
      @last_service_time = Time.now
    end
    
    def service_deficit(current_round_time)
      # Calculate how much service this flow is behind
      expected_service = current_round_time * @weight
      actual_service = @virtual_time * @weight
      expected_service - actual_service
    end
  end
  
  # Traffic shaper for bandwidth control
  class TrafficShaper
    attr_reader :bandwidth_bps, :burst_size, :queue
    
    def initialize(bandwidth_bps, burst_factor = 1.5)
      @bandwidth_bps = bandwidth_bps
      @burst_size = (bandwidth_bps * burst_factor).to_i
      @token_bucket = TokenBucket.new(bandwidth_bps, @burst_size)
      @queue = []
      @shaping_enabled = true
    end
    
    def shape_packet(packet)
      packet_size_bits = packet.size * 8
      
      if @shaping_enabled && !@token_bucket.consume(packet.size)
        # Packet exceeds rate limit, queue it
        @queue << {
          packet: packet,
          enqueue_time: Time.now,
          size: packet.size
        }
        return :queued
      end
      
      :transmitted
    end
    
    def process_queue
      sent_packets = []
      
      @queue.reject! do |queued_packet|
        if @token_bucket.consume(queued_packet[:size])
          sent_packets << queued_packet[:packet]
          true  # Remove from queue
        else
          false  # Keep in queue
        end
      end
      
      sent_packets
    end
    
    def get_queue_delay
      return 0 if @queue.empty?
      
      oldest_packet = @queue.min_by { |p| p[:enqueue_time] }
      (Time.now - oldest_packet[:enqueue_time]) * 1000  # ms
    end
  end
  
  # QoS statistics collection
  class QoSStats
    def initialize
      @stats = {
        packets_enqueued: 0,
        packets_dequeued: 0,
        packets_dropped: 0,
        packets_transmitted: 0,
        bytes_transmitted: 0,
        total_latency_ms: 0.0,
        sla_violations: 0,
        drop_reasons: Hash.new(0),
        start_time: Time.now
      }
      @mutex = Mutex.new
    end
    
    def packet_enqueued(qos_class)
      @mutex.synchronize do
        @stats[:packets_enqueued] += 1
      end
    end
    
    def packet_dequeued(qos_class, latency_ms)
      @mutex.synchronize do
        @stats[:packets_dequeued] += 1
        @stats[:total_latency_ms] += latency_ms
      end
    end
    
    def packet_dropped(qos_class, reason)
      @mutex.synchronize do
        @stats[:packets_dropped] += 1
        @stats[:drop_reasons][reason] += 1
      end
    end
    
    def packet_transmitted(qos_class, bytes)
      @mutex.synchronize do
        @stats[:packets_transmitted] += 1
        @stats[:bytes_transmitted] += bytes
      end
    end
    
    def sla_violation(qos_class)
      @mutex.synchronize do
        @stats[:sla_violations] += 1
      end
    end
    
    def to_hash
      @mutex.synchronize do
        uptime = Time.now - @stats[:start_time]
        packets_processed = @stats[:packets_dequeued]
        
        @stats.merge({
          uptime_seconds: uptime.round,
          avg_latency_ms: packets_processed > 0 ? (@stats[:total_latency_ms] / packets_processed).round(2) : 0,
          throughput_bps: uptime > 0 ? (@stats[:bytes_transmitted] * 8 / uptime).round : 0,
          drop_rate_percent: @stats[:packets_enqueued] > 0 ? 
            ((@stats[:packets_dropped].to_f / @stats[:packets_enqueued]) * 100).round(2) : 0
        })
      end
    end
  end
  
  # Per-class statistics
  class ClassStats
    def initialize(class_name)
      @class_name = class_name
      @stats = {
        packets_enqueued: 0,
        packets_transmitted: 0,
        bytes_transmitted: 0,
        packets_dropped: 0,
        latency_violations: 0,
        avg_latency_ms: 0.0,
        bandwidth_utilization: 0.0
      }
      @latencies = []
      @mutex = Mutex.new
    end
    
    def record_transmission(bytes, latency_ms = nil)
      @mutex.synchronize do
        @stats[:packets_transmitted] += 1
        @stats[:bytes_transmitted] += bytes
        
        if latency_ms
          @latencies << latency_ms
          @latencies = @latencies.last(1000)  # Keep last 1000 measurements
          @stats[:avg_latency_ms] = @latencies.sum / @latencies.size
        end
      end
    end
    
    def record_drop
      @mutex.synchronize do
        @stats[:packets_dropped] += 1
      end
    end
    
    def record_latency_violation
      @mutex.synchronize do
        @stats[:latency_violations] += 1
      end
    end
    
    def to_hash
      @mutex.synchronize do
        @stats.dup
      end
    end
  end
end