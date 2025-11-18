# frozen_string_literal: true

module RubyNetStack
  # HexPresenter provides utilities for formatting binary data as hex dumps
  # This is essential for debugging raw network packets at the byte level
  class HexPresenter
    # Default number of bytes per line in hex dump
    DEFAULT_WIDTH = 16
    
    # Convert binary data to a formatted hex dump
    def self.hex_dump(data, width = DEFAULT_WIDTH, show_ascii = true)
      return "" if data.nil? || data.empty?
      
      lines = []
      offset = 0
      
      while offset < data.length
        # Extract chunk of data for this line
        chunk = data[offset, width]
        
        # Format offset
        offset_str = sprintf("%08x", offset)
        
        # Format hex bytes with spacing
        hex_str = chunk.unpack("C*").map { |b| sprintf("%02x", b) }
        
        # Pad hex string to maintain alignment
        while hex_str.length < width
          hex_str << "  "
        end
        
        # Add extra spacing every 8 bytes for readability
        hex_formatted = hex_str.each_slice(8).map { |slice| slice.join(" ") }.join("  ")
        
        # Create ASCII representation if requested
        ascii_str = ""
        if show_ascii
          ascii_str = " |" + chunk.bytes.map { |b| 
            (b >= 32 && b <= 126) ? b.chr : "."
          }.join + "|"
        end
        
        lines << "#{offset_str}  #{hex_formatted}#{ascii_str}"
        offset += width
      end
      
      lines.join("\n")
    end
    
    # Convert binary data to a simple hex string
    def self.to_hex_string(data, separator = "")
      return "" if data.nil? || data.empty?
      data.unpack("C*").map { |b| sprintf("%02x", b) }.join(separator)
    end
    
    # Format MAC address bytes nicely
    def self.format_mac(data)
      return "00:00:00:00:00:00" if data.nil? || data.length != 6
      data.unpack("C6").map { |b| sprintf("%02x", b) }.join(":")
    end
    
    # Format IP address bytes (4 bytes) to dotted decimal
    def self.format_ip(data)
      return "0.0.0.0" if data.nil? || data.length != 4
      data.unpack("C4").join(".")
    end
    
    # Format bytes with bit representation for detailed analysis
    def self.binary_dump(data, bytes_per_line = 4)
      return "" if data.nil? || data.empty?
      
      lines = []
      offset = 0
      
      while offset < data.length
        chunk = data[offset, bytes_per_line]
        
        # Hex representation
        hex_line = chunk.unpack("C*").map { |b| sprintf("%02x", b) }.join(" ")
        
        # Binary representation
        bin_line = chunk.unpack("C*").map { |b| sprintf("%08b", b) }.join(" ")
        
        lines << sprintf("%04x: %-#{bytes_per_line * 3}s %s", offset, hex_line, bin_line)
        offset += bytes_per_line
      end
      
      lines.join("\n")
    end
    
    # Highlight specific bytes in hex dump
    def self.highlight_bytes(data, start_pos, length, marker = "**")
      hex_str = to_hex_string(data, " ")
      bytes = hex_str.split(" ")
      
      # Add markers around specified range
      (start_pos...start_pos + length).each do |i|
        bytes[i] = "#{marker}#{bytes[i]}#{marker}" if bytes[i]
      end
      
      bytes.join(" ")
    end
    
    # Create a side-by-side comparison of two data blocks
    def self.compare_hex(data1, data2, label1 = "Data 1", label2 = "Data 2")
      max_length = [data1&.length || 0, data2&.length || 0].max
      return "" if max_length == 0
      
      lines = []
      lines << "#{label1.ljust(35)} | #{label2}"
      lines << "-" * 75
      
      (0...max_length).step(16) do |offset|
        chunk1 = data1 ? data1[offset, 16] : ""
        chunk2 = data2 ? data2[offset, 16] : ""
        
        hex1 = chunk1.unpack("C*").map { |b| sprintf("%02x", b) }.join(" ").ljust(47)
        hex2 = chunk2.unpack("C*").map { |b| sprintf("%02x", b) }.join(" ")
        
        lines << "#{hex1} | #{hex2}"
      end
      
      lines.join("\n")
    end
  end
end