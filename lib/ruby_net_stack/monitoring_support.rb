# frozen_string_literal: true

module RubyNetStack
  # MetricsStorage provides time-series data storage and querying capabilities
  class MetricsStorage
    attr_reader :retention_days, :total_points
    
    def initialize(retention_days = 7)
      @retention_days = retention_days
      @data = {}  # timestamp => metrics_hash
      @indices = {}  # metric_name => sorted_timestamps
      @total_points = 0
      @mutex = Mutex.new
      
      # Start cleanup thread
      start_cleanup_thread
    end
    
    # Store metrics data with timestamp
    def store(timestamp, metrics_hash)
      @mutex.synchronize do
        @data[timestamp] = metrics_hash
        @total_points += 1
        
        # Update indices for faster querying
        metrics_hash.each_key do |metric_name|
          @indices[metric_name] ||= []
          @indices[metric_name] << timestamp
          @indices[metric_name].sort!
        end
      end
    end
    
    # Query metrics data within time range
    def query(start_time, end_time, granularity = :minute)
      @mutex.synchronize do
        # Filter data by time range
        filtered_data = @data.select do |timestamp, _|
          timestamp >= start_time && timestamp <= end_time
        end
        
        case granularity
        when :raw
          filtered_data
        when :second
          aggregate_by_second(filtered_data)
        when :minute
          aggregate_by_minute(filtered_data)
        when :hour
          aggregate_by_hour(filtered_data)
        when :day
          aggregate_by_day(filtered_data)
        else
          filtered_data
        end
      end
    end
    
    # Get latest metrics
    def get_latest
      @mutex.synchronize do
        return {} if @data.empty?
        
        latest_timestamp = @data.keys.max
        @data[latest_timestamp]
      end
    end
    
    # Get metrics for specific metric name
    def get_metric_series(metric_name, start_time, end_time)
      @mutex.synchronize do
        timestamps = @indices[metric_name] || []
        relevant_timestamps = timestamps.select { |ts| ts >= start_time && ts <= end_time }
        
        relevant_timestamps.map do |timestamp|
          {
            timestamp: timestamp,
            value: @data[timestamp]&.dig(metric_name)
          }
        end.compact
      end
    end
    
    # Clear old data beyond retention period
    def cleanup_old_data
      @mutex.synchronize do
        cutoff_time = Time.now - (@retention_days * 24 * 3600)
        
        old_timestamps = @data.keys.select { |ts| ts < cutoff_time }
        old_timestamps.each do |timestamp|
          @data.delete(timestamp)
          @total_points -= 1
          
          # Clean up indices
          @indices.each do |metric_name, timestamps|
            timestamps.delete(timestamp)
          end
        end
        
        puts "Cleaned up #{old_timestamps.size} old data points"
      end
    end
    
    # Get storage statistics
    def get_stats
      @mutex.synchronize do
        {
          total_points: @total_points,
          metrics_tracked: @indices.keys.size,
          oldest_data: @data.keys.min,
          latest_data: @data.keys.max,
          retention_days: @retention_days,
          memory_usage_mb: calculate_memory_usage
        }
      end
    end
    
    private
    
    def start_cleanup_thread
      Thread.new do
        loop do
          sleep(3600)  # Run cleanup every hour
          cleanup_old_data
        end
      end
    end
    
    def aggregate_by_second(data)
      aggregate_by_time_bucket(data, 1)
    end
    
    def aggregate_by_minute(data)
      aggregate_by_time_bucket(data, 60)
    end
    
    def aggregate_by_hour(data)
      aggregate_by_time_bucket(data, 3600)
    end
    
    def aggregate_by_day(data)
      aggregate_by_time_bucket(data, 86400)
    end
    
    def aggregate_by_time_bucket(data, bucket_size)
      buckets = {}
      
      data.each do |timestamp, metrics|
        bucket_key = (timestamp.to_i / bucket_size) * bucket_size
        bucket_time = Time.at(bucket_key)
        
        buckets[bucket_time] ||= []
        buckets[bucket_time] << metrics
      end
      
      # Aggregate metrics within each bucket
      buckets.transform_values do |bucket_data|
        aggregate_metrics(bucket_data)
      end
    end
    
    def aggregate_metrics(metrics_array)
      return {} if metrics_array.empty?
      
      aggregated = {}
      
      metrics_array.each do |metrics|
        metrics.each do |key, value|
          if value.is_a?(Numeric)
            aggregated[key] ||= []
            aggregated[key] << value
          elsif value.is_a?(Hash)
            # Handle nested metrics
            aggregated[key] ||= []
            aggregated[key] << value
          end
        end
      end
      
      # Calculate averages for numeric values
      aggregated.transform_values do |values|
        if values.first.is_a?(Numeric)
          {
            avg: values.sum.to_f / values.size,
            min: values.min,
            max: values.max,
            count: values.size
          }
        else
          values.last  # Take most recent for non-numeric
        end
      end
    end
    
    def calculate_memory_usage
      # Rough estimation of memory usage
      (@data.size * 1024) / (1024 * 1024)  # Convert to MB
    end
  end
  
  # AlertManager handles alert rules, notifications, and escalations
  class AlertManager
    attr_reader :rules, :active_alerts, :notifications
    
    def initialize
      @rules = []
      @active_alerts = {}
      @notifications = []
      @processing = false
      @escalation_rules = {}
      @notification_channels = {}
      @alert_history = []
      @mutex = Mutex.new
      
      setup_default_channels
    end
    
    # Add alert rule
    def add_rule(rule)
      @mutex.synchronize do
        @rules << AlertRule.new(rule)
      end
      puts "Added alert rule: #{rule[:name]}"
    end
    
    # Remove alert rule
    def remove_rule(rule_id)
      @mutex.synchronize do
        @rules.reject! { |rule| rule.id == rule_id }
      end
    end
    
    # Start alert processing
    def start_processing
      return if @processing
      
      @processing = true
      puts "Alert processing started"
    end
    
    # Stop alert processing
    def stop_processing
      @processing = false
      puts "Alert processing stopped"
    end
    
    # Process current metrics against alert rules
    def process_metrics(metrics)
      return unless @processing
      
      @rules.each do |rule|
        result = rule.evaluate(metrics)
        next unless result[:triggered]
        
        handle_alert(rule, result)
      end
    end
    
    # Process analysis results from analyzers
    def process_analysis_results(analyzer_name, results)
      return unless @processing
      
      # Check if results contain alerts
      if results[:anomalies]
        results[:anomalies].each do |anomaly|
          create_analysis_alert(analyzer_name, anomaly)
        end
      end
      
      if results[:threat_level] && results[:threat_level] != "Low"
        create_threat_alert(analyzer_name, results)
      end
    end
    
    # Get active alert count
    def active_alert_count
      @active_alerts.size
    end
    
    # Get alert summary for time range
    def get_summary(start_time, end_time)
      relevant_alerts = @alert_history.select do |alert|
        alert[:created_at] >= start_time && alert[:created_at] <= end_time
      end
      
      {
        total_alerts: relevant_alerts.size,
        critical_alerts: relevant_alerts.count { |a| a[:severity] == :critical },
        high_alerts: relevant_alerts.count { |a| a[:severity] == :high },
        medium_alerts: relevant_alerts.count { |a| a[:severity] == :medium },
        low_alerts: relevant_alerts.count { |a| a[:severity] == :low },
        top_alert_types: get_top_alert_types(relevant_alerts)
      }
    end
    
    # Configure notification channel
    def add_notification_channel(name, config)
      @notification_channels[name] = NotificationChannel.new(name, config)
      puts "Added notification channel: #{name}"
    end
    
    # Get all alerts (active and resolved)
    def get_all_alerts
      {
        active: @active_alerts.values,
        history: @alert_history.last(100)
      }
    end
    
    private
    
    def handle_alert(rule, result)
      alert_id = "#{rule.id}-#{Time.now.to_i}"
      
      @mutex.synchronize do
        if @active_alerts[alert_id]
          # Update existing alert
          @active_alerts[alert_id][:count] += 1
          @active_alerts[alert_id][:last_triggered] = Time.now
        else
          # Create new alert
          alert = {
            id: alert_id,
            rule_id: rule.id,
            rule_name: rule.name,
            severity: rule.severity,
            message: result[:message],
            details: result[:details],
            created_at: Time.now,
            last_triggered: Time.now,
            count: 1,
            status: :active,
            acknowledged: false
          }
          
          @active_alerts[alert_id] = alert
          @alert_history << alert.dup
          
          # Send notifications
          send_notifications(alert)
        end
      end
    end
    
    def create_analysis_alert(analyzer_name, anomaly)
      alert = {
        id: "#{analyzer_name}-#{SecureRandom.uuid}",
        type: :analysis,
        analyzer: analyzer_name,
        severity: anomaly[:severity] || :medium,
        message: "#{anomaly[:type]} detected by #{analyzer_name}",
        details: anomaly,
        created_at: Time.now,
        status: :active,
        acknowledged: false
      }
      
      @mutex.synchronize do
        @active_alerts[alert[:id]] = alert
        @alert_history << alert.dup
      end
      
      send_notifications(alert)
    end
    
    def create_threat_alert(analyzer_name, results)
      alert = {
        id: "threat-#{SecureRandom.uuid}",
        type: :security_threat,
        analyzer: analyzer_name,
        severity: map_threat_level_to_severity(results[:threat_level]),
        message: "#{results[:threat_level]} threat level detected",
        details: results,
        created_at: Time.now,
        status: :active,
        acknowledged: false
      }
      
      @mutex.synchronize do
        @active_alerts[alert[:id]] = alert
        @alert_history << alert.dup
      end
      
      send_notifications(alert)
    end
    
    def send_notifications(alert)
      @notification_channels.each do |name, channel|
        begin
          channel.send_notification(alert) if channel.should_notify?(alert)
        rescue => e
          puts "Notification channel #{name} failed: #{e.message}"
        end
      end
    end
    
    def setup_default_channels
      # Console notification channel
      @notification_channels[:console] = NotificationChannel.new(:console, {
        type: :console,
        min_severity: :medium
      })
    end
    
    def map_threat_level_to_severity(threat_level)
      case threat_level.downcase
      when "critical" then :critical
      when "high" then :high
      when "medium" then :medium
      when "low" then :low
      else :medium
      end
    end
    
    def get_top_alert_types(alerts)
      type_counts = alerts.group_by { |a| a[:rule_name] || a[:type] }
                           .transform_values(&:count)
      
      type_counts.sort_by { |_, count| -count }.first(5).to_h
    end
  end
  
  # Individual alert rule
  class AlertRule
    attr_reader :id, :name, :condition, :severity, :enabled
    
    def initialize(config)
      @id = config[:id] || SecureRandom.uuid
      @name = config[:name]
      @condition = config[:condition]
      @severity = config[:severity] || :medium
      @enabled = config[:enabled] != false
      @threshold = config[:threshold]
      @metric_path = config[:metric_path]
      @operator = config[:operator] || :greater_than
      @time_window = config[:time_window] || 60  # seconds
      @min_occurrences = config[:min_occurrences] || 1
      @last_triggered = nil
      @occurrence_count = 0
    end
    
    def evaluate(metrics)
      return { triggered: false } unless @enabled
      
      metric_value = extract_metric_value(metrics, @metric_path)
      return { triggered: false } if metric_value.nil?
      
      condition_met = evaluate_condition(metric_value)
      
      if condition_met
        @occurrence_count += 1
        @last_triggered = Time.now
        
        if @occurrence_count >= @min_occurrences
          return {
            triggered: true,
            message: build_alert_message(metric_value),
            details: {
              metric_path: @metric_path,
              threshold: @threshold,
              actual_value: metric_value,
              operator: @operator,
              occurrence_count: @occurrence_count
            }
          }
        end
      else
        # Reset occurrence count if condition is not met
        @occurrence_count = 0
      end
      
      { triggered: false }
    end
    
    private
    
    def extract_metric_value(metrics, path)
      path_parts = path.split('.')
      current = metrics
      
      path_parts.each do |part|
        return nil unless current.is_a?(Hash)
        current = current[part.to_sym] || current[part]
        return nil if current.nil?
      end
      
      current
    end
    
    def evaluate_condition(value)
      case @operator
      when :greater_than
        value > @threshold
      when :less_than
        value < @threshold
      when :equal_to
        value == @threshold
      when :not_equal_to
        value != @threshold
      when :greater_than_or_equal
        value >= @threshold
      when :less_than_or_equal
        value <= @threshold
      else
        false
      end
    end
    
    def build_alert_message(value)
      "#{@name}: #{@metric_path} is #{value} (threshold: #{@operator} #{@threshold})"
    end
  end
  
  # Notification channel for alert delivery
  class NotificationChannel
    attr_reader :name, :type, :config
    
    def initialize(name, config)
      @name = name
      @type = config[:type]
      @config = config
      @min_severity = config[:min_severity] || :low
      @rate_limit = config[:rate_limit] || 60  # seconds between notifications
      @last_notification = {}
    end
    
    def should_notify?(alert)
      # Check severity threshold
      severity_levels = { low: 1, medium: 2, high: 3, critical: 4 }
      alert_level = severity_levels[alert[:severity]] || 0
      min_level = severity_levels[@min_severity] || 0
      
      return false if alert_level < min_level
      
      # Check rate limiting
      key = "#{alert[:rule_id]}-#{alert[:type]}"
      return false if rate_limited?(key)
      
      true
    end
    
    def send_notification(alert)
      case @type
      when :console
        send_console_notification(alert)
      when :email
        send_email_notification(alert)
      when :slack
        send_slack_notification(alert)
      when :webhook
        send_webhook_notification(alert)
      else
        puts "Unknown notification type: #{@type}"
      end
      
      # Update rate limiting
      key = "#{alert[:rule_id]}-#{alert[:type]}"
      @last_notification[key] = Time.now
    end
    
    private
    
    def rate_limited?(key)
      last_time = @last_notification[key]
      return false unless last_time
      
      (Time.now - last_time) < @rate_limit
    end
    
    def send_console_notification(alert)
      severity_emoji = {
        low: "ℹ️",
        medium: "⚠️",
        high: "🚨",
        critical: "🔥"
      }
      
      puts "\\n#{severity_emoji[alert[:severity]]} ALERT [#{alert[:severity].upcase}]"
      puts "Rule: #{alert[:rule_name] || alert[:type]}"
      puts "Message: #{alert[:message]}"
      puts "Time: #{alert[:created_at] || alert[:last_triggered]}"
      
      if alert[:details]
        puts "Details: #{alert[:details].inspect}"
      end
      
      puts "-" * 50
    end
    
    def send_email_notification(alert)
      # Placeholder for email notification
      puts "Email notification sent for alert: #{alert[:message]}"
    end
    
    def send_slack_notification(alert)
      # Placeholder for Slack notification
      puts "Slack notification sent for alert: #{alert[:message]}"
    end
    
    def send_webhook_notification(alert)
      # Placeholder for webhook notification
      puts "Webhook notification sent for alert: #{alert[:message]}"
    end
  end
  
  # Dashboard management for visualization
  class DashboardManager
    def initialize
      @dashboards = {}
    end
    
    def create_dashboard(name, config)
      @dashboards[name] = NetworkDashboard.new(name, config)
      puts "Created dashboard: #{name}"
    end
    
    def get_dashboard(name)
      @dashboards[name]
    end
    
    def list_dashboards
      @dashboards.keys
    end
    
    def remove_dashboard(name)
      @dashboards.delete(name)
      puts "Removed dashboard: #{name}"
    end
  end
  
  # Network dashboard for metrics visualization
  class NetworkDashboard
    attr_reader :name, :widgets, :refresh_interval
    
    def initialize(name, config = {})
      @name = name
      @widgets = config[:widgets] || []
      @refresh_interval = config[:refresh_interval] || 60
      @layout = config[:layout] || :grid
    end
    
    def add_widget(widget_config)
      widget = DashboardWidget.new(widget_config)
      @widgets << widget
      puts "Added widget: #{widget_config[:title]}"
    end
    
    def remove_widget(widget_id)
      @widgets.reject! { |w| w.id == widget_id }
    end
    
    def render(metrics_data)
      output = "\\n" + "="*60
      output += "\\nDASHBOARD: #{@name}"
      output += "\\n" + "="*60
      
      @widgets.each do |widget|
        output += "\\n\\n#{widget.render(metrics_data)}"
      end
      
      output += "\\n" + "="*60 + "\\n"
      output
    end
    
    def to_json(metrics_data)
      {
        name: @name,
        refresh_interval: @refresh_interval,
        layout: @layout,
        widgets: @widgets.map { |w| w.to_hash(metrics_data) },
        last_updated: Time.now
      }.to_json
    end
  end
  
  # Individual dashboard widget
  class DashboardWidget
    attr_reader :id, :title, :type, :metric_path, :config
    
    def initialize(config)
      @id = config[:id] || SecureRandom.uuid
      @title = config[:title]
      @type = config[:type]  # :gauge, :chart, :table, :text
      @metric_path = config[:metric_path]
      @config = config
    end
    
    def render(metrics_data)
      case @type
      when :gauge
        render_gauge(metrics_data)
      when :chart
        render_chart(metrics_data)
      when :table
        render_table(metrics_data)
      when :text
        render_text(metrics_data)
      else
        "Unknown widget type: #{@type}"
      end
    end
    
    def to_hash(metrics_data)
      {
        id: @id,
        title: @title,
        type: @type,
        data: extract_widget_data(metrics_data),
        config: @config
      }
    end
    
    private
    
    def render_gauge(metrics_data)
      value = extract_metric_value(metrics_data)
      max_value = @config[:max_value] || 100
      
      percentage = (value.to_f / max_value * 100).round(1)
      bar_length = 20
      filled_length = (percentage / 100 * bar_length).round
      
      bar = "#" * filled_length + "-" * (bar_length - filled_length)
      
      "#{@title}: [#{bar}] #{value}/#{max_value} (#{percentage}%)"
    end
    
    def render_chart(metrics_data)
      # Simplified chart rendering
      "#{@title}: [Chart] Latest: #{extract_metric_value(metrics_data)}"
    end
    
    def render_table(metrics_data)
      # Simplified table rendering
      "#{@title}:\\n  Value: #{extract_metric_value(metrics_data)}"
    end
    
    def render_text(metrics_data)
      "#{@title}: #{extract_metric_value(metrics_data)}"
    end
    
    def extract_metric_value(metrics_data)
      return "N/A" unless @metric_path
      
      path_parts = @metric_path.split('.')
      current = metrics_data
      
      path_parts.each do |part|
        return "N/A" unless current.is_a?(Hash)
        current = current[part.to_sym] || current[part]
        return "N/A" if current.nil?
      end
      
      current
    end
    
    def extract_widget_data(metrics_data)
      extract_metric_value(metrics_data)
    end
  end
  
  # Network topology discovery
  class TopologyDiscovery
    def initialize
      @discovered_devices = {}
      @connections = []
    end
    
    def discover
      # Simplified topology discovery
      {
        devices: discover_devices,
        connections: discover_connections,
        subnets: discover_subnets,
        routes: discover_routes
      }
    end
    
    private
    
    def discover_devices
      # Placeholder device discovery
      [
        { ip: "192.168.1.1", type: "router", mac: "00:11:22:33:44:55" },
        { ip: "192.168.1.10", type: "server", mac: "00:aa:bb:cc:dd:ee" },
        { ip: "192.168.1.100", type: "workstation", mac: "00:ff:ee:dd:cc:bb" }
      ]
    end
    
    def discover_connections
      # Placeholder connection discovery
      [
        { from: "192.168.1.1", to: "192.168.1.10", protocol: "TCP", port: 80 },
        { from: "192.168.1.1", to: "192.168.1.100", protocol: "TCP", port: 22 }
      ]
    end
    
    def discover_subnets
      # Placeholder subnet discovery
      ["192.168.1.0/24", "10.0.0.0/8"]
    end
    
    def discover_routes
      # Placeholder route discovery
      [
        { destination: "0.0.0.0/0", gateway: "192.168.1.1", interface: "eth0" },
        { destination: "192.168.1.0/24", gateway: nil, interface: "eth0" }
      ]
    end
  end
end