# frozen_string_literal: true

module RubyNetStack
  # DNSResolver provides comprehensive DNS resolution capabilities including
  # recursive queries, caching, and authoritative responses
  class DNSResolver
    attr_reader :cache, :stats, :upstream_servers, :zones
    
    # DNS record types
    RECORD_TYPES = {
      A: 1, AAAA: 28, CNAME: 5, MX: 15, NS: 2, PTR: 12, SOA: 6, TXT: 16, SRV: 33
    }
    
    # DNS response codes
    RESPONSE_CODES = {
      NOERROR: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3, NOTIMP: 4, REFUSED: 5
    }
    
    def initialize(options = {})
      @cache = DNSCache.new(options[:cache_size] || 10000)
      @stats = DNSStats.new
      @upstream_servers = options[:upstream_servers] || ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
      @zones = {}  # Authoritative zones
      @listen_port = options[:listen_port] || 53
      @recursive = options[:recursive] != false
      @authoritative = options[:authoritative] || false
      @running = false
      @server_thread = nil
      @request_id = 0
      
      initialize_root_hints
    end
    
    # Start DNS server
    def start_server(bind_ip = "0.0.0.0")
      return if @running
      
      @running = true
      @server_thread = Thread.new do
        begin
          socket = UDPSocket.new
          socket.bind(bind_ip, @listen_port)
          
          puts "DNS Server started on #{bind_ip}:#{@listen_port}"
          
          while @running
            begin
              data, client_info = socket.recvfrom(512)
              Thread.new { handle_dns_request(data, client_info, socket) }
            rescue => e
              puts "DNS Server error: #{e.message}" unless !@running
            end
          end
        rescue => e
          puts "DNS Server fatal error: #{e.message}"
        ensure
          socket&.close
        end
      end
    end
    
    # Stop DNS server
    def stop_server
      @running = false
      @server_thread&.join
      puts "DNS Server stopped"
    end
    
    # Resolve domain name
    def resolve(domain, record_type = :A, recursive = true)
      @stats.query_received(record_type)
      
      # Normalize domain name
      domain = domain.downcase.chomp(".")
      cache_key = "#{domain}:#{record_type}"
      
      # Check cache first
      cached_result = @cache.get(cache_key)
      if cached_result
        @stats.cache_hit
        return cached_result
      end
      
      @stats.cache_miss
      
      # Check if we're authoritative for this domain
      if @authoritative
        result = resolve_authoritative(domain, record_type)
        if result
          @cache.put(cache_key, result, result[:ttl] || 300)
          return result
        end
      end
      
      # Recursive resolution if enabled
      if recursive && @recursive
        result = resolve_recursive(domain, record_type)
      else
        result = resolve_iterative(domain, record_type)
      end
      
      # Cache successful results
      if result && result[:rcode] == RESPONSE_CODES[:NOERROR]
        ttl = result[:answers].map { |ans| ans[:ttl] }.min || 300
        @cache.put(cache_key, result, ttl)
      end
      
      result
    end
    
    # Add authoritative zone
    def add_zone(zone_name, zone_data)
      zone = DNSZone.new(zone_name, zone_data)
      @zones[zone_name.downcase] = zone
      puts "Added authoritative zone: #{zone_name}"
    end
    
    # Remove authoritative zone
    def remove_zone(zone_name)
      @zones.delete(zone_name.downcase)
      puts "Removed authoritative zone: #{zone_name}"
    end
    
    # Add static DNS record
    def add_static_record(domain, record_type, value, ttl = 300)
      domain = domain.downcase.chomp(".")
      
      record = {
        name: domain,
        type: record_type,
        value: value,
        ttl: ttl,
        class: :IN
      }
      
      # Find or create zone for domain
      zone_name = extract_zone_name(domain)
      @zones[zone_name] ||= DNSZone.new(zone_name)
      @zones[zone_name].add_record(record)
      
      puts "Added static record: #{domain} #{record_type} #{value}"
    end
    
    # Flush DNS cache
    def flush_cache
      @cache.clear
      puts "DNS cache flushed"
    end
    
    # Get DNS statistics
    def get_stats
      {
        queries: @stats.to_hash,
        cache: @cache.get_stats,
        zones: @zones.keys,
        upstream_servers: @upstream_servers,
        running: @running
      }
    end
    
    private
    
    def handle_dns_request(data, client_info, socket)
      begin
        request = parse_dns_packet(data)
        return unless request
        
        @stats.query_received(request[:questions].first[:type])
        
        # Process the first question (standard behavior)
        question = request[:questions].first
        result = resolve(question[:name], question[:type])
        
        # Build response
        response = build_dns_response(request, result)
        response_data = serialize_dns_packet(response)
        
        # Send response
        socket.send(response_data, 0, client_info[3], client_info[1])
        @stats.response_sent(result[:rcode])
        
      rescue => e
        puts "Error handling DNS request: #{e.message}"
        # Send SERVFAIL response
        error_response = build_error_response(request, RESPONSE_CODES[:SERVFAIL])
        socket.send(serialize_dns_packet(error_response), 0, client_info[3], client_info[1])
      end
    end
    
    def resolve_authoritative(domain, record_type)
      zone_name = find_authoritative_zone(domain)
      return nil unless zone_name
      
      zone = @zones[zone_name]
      records = zone.find_records(domain, record_type)
      
      return nil if records.empty?
      
      {
        rcode: RESPONSE_CODES[:NOERROR],
        authoritative: true,
        answers: records.map { |r| format_answer_record(r) },
        authority: [zone.soa_record].compact.map { |r| format_answer_record(r) },
        additional: []
      }
    end
    
    def resolve_recursive(domain, record_type)
      # Start from root servers and work down
      nameservers = @root_hints.dup
      
      # Iterative queries following referrals
      loop do
        nameserver = nameservers.first
        break unless nameserver
        
        response = query_nameserver(nameserver, domain, record_type)
        return format_error_response(RESPONSE_CODES[:SERVFAIL]) unless response
        
        case response[:rcode]
        when RESPONSE_CODES[:NOERROR]
          if response[:answers] && !response[:answers].empty?
            # Got answer
            return response
          elsif response[:authority] && !response[:authority].empty?
            # Got referral, follow it
            nameservers = extract_nameservers(response[:authority], response[:additional])
            next
          else
            return format_error_response(RESPONSE_CODES[:NXDOMAIN])
          end
        when RESPONSE_CODES[:NXDOMAIN]
          return response
        else
          # Try next nameserver
          nameservers.shift
        end
      end
      
      format_error_response(RESPONSE_CODES[:SERVFAIL])
    end
    
    def resolve_iterative(domain, record_type)
      # Try upstream servers in order
      @upstream_servers.each do |server|
        begin
          response = query_nameserver(server, domain, record_type)
          return response if response
        rescue => e
          puts "Upstream server #{server} failed: #{e.message}"
          next
        end
      end
      
      format_error_response(RESPONSE_CODES[:SERVFAIL])
    end
    
    def query_nameserver(server, domain, record_type, timeout = 5)
      socket = UDPSocket.new
      socket.bind("0.0.0.0", 0)
      
      # Build DNS query
      query = build_dns_query(domain, record_type)
      query_data = serialize_dns_packet(query)
      
      # Send query
      socket.send(query_data, 0, server, 53)
      
      # Wait for response with timeout
      if IO.select([socket], nil, nil, timeout)
        response_data = socket.recv(512)
        response = parse_dns_packet(response_data)
        return response
      end
      
      nil
    ensure
      socket&.close
    end
    
    def build_dns_query(domain, record_type)
      {
        id: (@request_id += 1) & 0xFFFF,
        flags: {
          qr: 0,     # Query
          opcode: 0, # Standard query
          aa: 0,     # Not authoritative
          tc: 0,     # Not truncated
          rd: 1,     # Recursion desired
          ra: 0,     # Recursion available
          z: 0,      # Reserved
          rcode: 0   # No error
        },
        questions: [{
          name: domain,
          type: RECORD_TYPES[record_type] || record_type,
          class: 1   # IN (Internet)
        }],
        answers: [],
        authority: [],
        additional: []
      }
    end
    
    def build_dns_response(request, resolution)
      {
        id: request[:id],
        flags: {
          qr: 1,     # Response
          opcode: 0, # Standard query
          aa: resolution[:authoritative] ? 1 : 0,
          tc: 0,     # Not truncated
          rd: request[:flags][:rd],
          ra: @recursive ? 1 : 0,
          z: 0,      # Reserved
          rcode: resolution[:rcode]
        },
        questions: request[:questions],
        answers: resolution[:answers] || [],
        authority: resolution[:authority] || [],
        additional: resolution[:additional] || []
      }
    end
    
    def parse_dns_packet(data)
      # Simplified DNS packet parsing
      return nil if data.length < 12
      
      header = data[0..11].unpack("n6")  # 6 16-bit values
      
      {
        id: header[0],
        flags: parse_flags(header[1]),
        qdcount: header[2],
        ancount: header[3],
        nscount: header[4],
        arcount: header[5],
        questions: parse_questions(data, 12, header[2]),
        answers: [],
        authority: [],
        additional: []
      }
    end
    
    def serialize_dns_packet(packet)
      # Simplified DNS packet serialization
      header = [
        packet[:id],
        serialize_flags(packet[:flags]),
        packet[:questions].length,
        packet[:answers].length,
        packet[:authority].length,
        packet[:additional].length
      ].pack("n6")
      
      questions_data = packet[:questions].map { |q| serialize_question(q) }.join
      answers_data = packet[:answers].map { |a| serialize_answer(a) }.join
      authority_data = packet[:authority].map { |a| serialize_answer(a) }.join
      additional_data = packet[:additional].map { |a| serialize_answer(a) }.join
      
      header + questions_data + answers_data + authority_data + additional_data
    end
    
    def parse_flags(flags_int)
      {
        qr: (flags_int >> 15) & 1,
        opcode: (flags_int >> 11) & 0xF,
        aa: (flags_int >> 10) & 1,
        tc: (flags_int >> 9) & 1,
        rd: (flags_int >> 8) & 1,
        ra: (flags_int >> 7) & 1,
        z: (flags_int >> 4) & 7,
        rcode: flags_int & 0xF
      }
    end
    
    def serialize_flags(flags)
      (flags[:qr] << 15) |
      (flags[:opcode] << 11) |
      (flags[:aa] << 10) |
      (flags[:tc] << 9) |
      (flags[:rd] << 8) |
      (flags[:ra] << 7) |
      (flags[:z] << 4) |
      flags[:rcode]
    end
    
    def parse_questions(data, offset, count)
      questions = []
      current_offset = offset
      
      count.times do
        name, new_offset = parse_domain_name(data, current_offset)
        type_class = data[new_offset..new_offset+3].unpack("nn")
        
        questions << {
          name: name,
          type: type_class[0],
          class: type_class[1]
        }
        
        current_offset = new_offset + 4
      end
      
      questions
    end
    
    def parse_domain_name(data, offset)
      labels = []
      current_offset = offset
      jumped = false
      original_offset = offset
      
      loop do
        return [labels.join("."), current_offset] if current_offset >= data.length
        
        length = data[current_offset].ord
        current_offset += 1
        
        if length == 0
          # End of domain name
          break
        elsif (length & 0xC0) == 0xC0
          # Compression pointer
          if !jumped
            original_offset = current_offset + 1
            jumped = true
          end
          pointer = ((length & 0x3F) << 8) | data[current_offset].ord
          current_offset = pointer
        else
          # Regular label
          labels << data[current_offset..current_offset+length-1]
          current_offset += length
        end
      end
      
      [labels.join("."), jumped ? original_offset : current_offset]
    end
    
    def serialize_question(question)
      name_data = serialize_domain_name(question[:name])
      type_class_data = [question[:type], question[:class]].pack("nn")
      name_data + type_class_data
    end
    
    def serialize_answer(answer)
      name_data = serialize_domain_name(answer[:name])
      header_data = [answer[:type], answer[:class], answer[:ttl]].pack("nnN")
      rdata = serialize_rdata(answer[:type], answer[:value])
      rdlength = [rdata.length].pack("n")
      
      name_data + header_data + rdlength + rdata
    end
    
    def serialize_domain_name(name)
      return "\x00" if name.empty?
      
      labels = name.split(".")
      result = ""
      
      labels.each do |label|
        result += [label.length].pack("C") + label
      end
      
      result + "\x00"
    end
    
    def serialize_rdata(record_type, value)
      case record_type
      when RECORD_TYPES[:A]
        # IPv4 address
        value.split(".").map(&:to_i).pack("CCCC")
      when RECORD_TYPES[:AAAA]
        # IPv6 address (simplified)
        [0] * 16  # Placeholder
      when RECORD_TYPES[:CNAME], RECORD_TYPES[:NS], RECORD_TYPES[:PTR]
        # Domain name
        serialize_domain_name(value)
      when RECORD_TYPES[:MX]
        # MX record: priority + domain name
        priority, domain = value.split(" ", 2)
        [priority.to_i].pack("n") + serialize_domain_name(domain)
      when RECORD_TYPES[:TXT]
        # Text record
        [value.length].pack("C") + value
      else
        value.to_s
      end
    end
    
    def initialize_root_hints
      # Simplified root hints (normally loaded from file)
      @root_hints = [
        "198.41.0.4",   # a.root-servers.net
        "199.9.14.201", # b.root-servers.net
        "192.33.4.12"   # c.root-servers.net
      ]
    end
    
    def find_authoritative_zone(domain)
      # Find the most specific zone that matches the domain
      domain_parts = domain.split(".")
      
      (0...domain_parts.length).each do |i|
        test_zone = domain_parts[i..-1].join(".")
        return test_zone if @zones.key?(test_zone)
      end
      
      nil
    end
    
    def extract_zone_name(domain)
      # Extract likely zone name from domain
      parts = domain.split(".")
      return domain if parts.length <= 2
      
      parts[-2..-1].join(".")  # Take last two parts as zone
    end
    
    def format_answer_record(record)
      {
        name: record[:name],
        type: RECORD_TYPES[record[:type]] || record[:type],
        class: 1,  # IN
        ttl: record[:ttl],
        value: record[:value]
      }
    end
    
    def format_error_response(rcode)
      {
        rcode: rcode,
        authoritative: false,
        answers: [],
        authority: [],
        additional: []
      }
    end
    
    def extract_nameservers(authority, additional)
      # Extract nameserver IPs from authority and additional sections
      nameservers = []
      
      authority.each do |auth_record|
        if auth_record[:type] == RECORD_TYPES[:NS]
          # Look for A record in additional section
          ns_name = auth_record[:value]
          additional.each do |add_record|
            if add_record[:name] == ns_name && add_record[:type] == RECORD_TYPES[:A]
              nameservers << add_record[:value]
            end
          end
        end
      end
      
      nameservers.empty? ? @upstream_servers : nameservers
    end
    
    def build_error_response(request, rcode)
      {
        id: request&.[](:id) || 0,
        flags: {
          qr: 1, opcode: 0, aa: 0, tc: 0, 
          rd: request&.dig(:flags, :rd) || 0, 
          ra: 0, z: 0, rcode: rcode
        },
        questions: request&.[](:questions) || [],
        answers: [],
        authority: [],
        additional: []
      }
    end
  end
  
  # DNS Cache implementation
  class DNSCache
    def initialize(max_size = 10000)
      @cache = {}
      @max_size = max_size
      @access_times = {}
      @mutex = Mutex.new
      @hits = 0
      @misses = 0
    end
    
    def get(key)
      @mutex.synchronize do
        entry = @cache[key]
        return nil unless entry
        
        # Check if entry has expired
        if Time.now > entry[:expires_at]
          @cache.delete(key)
          @access_times.delete(key)
          @misses += 1
          return nil
        end
        
        @access_times[key] = Time.now
        @hits += 1
        entry[:value]
      end
    end
    
    def put(key, value, ttl)
      @mutex.synchronize do
        # Evict oldest entries if cache is full
        if @cache.size >= @max_size
          evict_lru
        end
        
        @cache[key] = {
          value: value,
          expires_at: Time.now + ttl
        }
        @access_times[key] = Time.now
      end
    end
    
    def clear
      @mutex.synchronize do
        @cache.clear
        @access_times.clear
        @hits = 0
        @misses = 0
      end
    end
    
    def get_stats
      @mutex.synchronize do
        total_requests = @hits + @misses
        hit_rate = total_requests > 0 ? (@hits.to_f / total_requests * 100).round(2) : 0
        
        {
          size: @cache.size,
          max_size: @max_size,
          hits: @hits,
          misses: @misses,
          hit_rate_percent: hit_rate
        }
      end
    end
    
    private
    
    def evict_lru
      # Remove least recently used entry
      oldest_key = @access_times.min_by { |k, v| v }&.first
      if oldest_key
        @cache.delete(oldest_key)
        @access_times.delete(oldest_key)
      end
    end
  end
  
  # DNS Zone management
  class DNSZone
    attr_reader :name, :records, :soa_record
    
    def initialize(name, zone_data = {})
      @name = name.downcase
      @records = Hash.new { |h, k| h[k] = [] }
      @soa_record = zone_data[:soa]
      @mutex = Mutex.new
      
      # Load initial records if provided
      if zone_data[:records]
        zone_data[:records].each { |record| add_record(record) }
      end
    end
    
    def add_record(record)
      @mutex.synchronize do
        key = "#{record[:name]}:#{record[:type]}"
        @records[key] << record
      end
    end
    
    def remove_record(name, record_type)
      @mutex.synchronize do
        key = "#{name.downcase}:#{record_type}"
        @records.delete(key)
      end
    end
    
    def find_records(name, record_type)
      @mutex.synchronize do
        key = "#{name.downcase}:#{record_type}"
        @records[key].dup
      end
    end
    
    def get_all_records
      @mutex.synchronize do
        @records.values.flatten
      end
    end
  end
  
  # DNS statistics collection
  class DNSStats
    def initialize
      @stats = {
        total_queries: 0,
        queries_by_type: Hash.new(0),
        responses_by_code: Hash.new(0),
        cache_hits: 0,
        cache_misses: 0,
        upstream_queries: 0,
        start_time: Time.now
      }
      @mutex = Mutex.new
    end
    
    def query_received(record_type)
      @mutex.synchronize do
        @stats[:total_queries] += 1
        @stats[:queries_by_type][record_type] += 1
      end
    end
    
    def response_sent(rcode)
      @mutex.synchronize do
        @stats[:responses_by_code][rcode] += 1
      end
    end
    
    def cache_hit
      @mutex.synchronize do
        @stats[:cache_hits] += 1
      end
    end
    
    def cache_miss
      @mutex.synchronize do
        @stats[:cache_misses] += 1
      end
    end
    
    def upstream_query
      @mutex.synchronize do
        @stats[:upstream_queries] += 1
      end
    end
    
    def to_hash
      @mutex.synchronize do
        uptime = Time.now - @stats[:start_time]
        
        @stats.merge({
          uptime_seconds: uptime.round,
          queries_per_second: uptime > 0 ? (@stats[:total_queries] / uptime).round(2) : 0,
          cache_hit_rate: calculate_cache_hit_rate
        })
      end
    end
    
    private
    
    def calculate_cache_hit_rate
      total = @stats[:cache_hits] + @stats[:cache_misses]
      return 0.0 if total == 0
      (@stats[:cache_hits].to_f / total * 100).round(2)
    end
  end
end