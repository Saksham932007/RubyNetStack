# RubyNetStack

A userspace network stack implementation in pure Ruby that interfaces directly with network cards using `PF_PACKET` and `SOCK_RAW`, bypassing the OS transport layer.

## 🎯 Project Overview

RubyNetStack is a educational and experimental network stack that demonstrates low-level network programming concepts in Ruby. It implements packet parsing and construction for Ethernet, ARP, IP, UDP, and ICMP protocols without relying on the kernel's network stack.

## ✨ Features

### Protocol Support
- **Ethernet (Layer 2)**: Frame parsing with MAC address extraction and EtherType detection
- **ARP (Address Resolution Protocol)**: Request/Reply handling with automatic ARP responses
- **IPv4 (Layer 3)**: Complete packet parsing including fragmentation and checksum validation  
- **UDP (Layer 4)**: Datagram parsing with port-based service detection
- **ICMP**: Echo Request/Reply (ping/pong) functionality

### Advanced Capabilities
- **Raw Socket Programming**: Direct `PF_PACKET` socket access for frame-level control
- **Packet Construction**: Build and inject custom packets onto the network
- **Checksum Validation**: RFC 1071 compliant Internet checksum implementation
- **Protocol Dispatching**: Automatic routing based on EtherType and IP protocol fields
- **Network Interface Control**: `ioctl` integration for interface management
- **Hex Debugging**: Comprehensive packet inspection and visualization tools

### Echo Services
- **UDP Echo Server**: Listens on port 4321, uppercases received strings
- **ICMP Auto-Reply**: Automatically responds to ping requests
- **ARP Resolution**: Responds to ARP requests for configured IP addresses

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application   │    │      ICMP       │    │      UDP        │
│     Layer       │    │   (ping/pong)   │    │ (echo server)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
┌─────────────────────────────────────────────────────────────────┐
│                    IP Packet (Layer 3)                         │
│  Version│IHL│TOS│Length│ID│Flags│Frag│TTL│Proto│Chksum│Src│Dst  │
└─────────────────────────────────────────────────────────────────┘
                                 │
┌─────────────────────────────────────────────────────────────────┐
│                 Ethernet Frame (Layer 2)                       │
│           Dest MAC │ Src MAC │ EtherType │ Payload              │
└─────────────────────────────────────────────────────────────────┘
                                 │
┌─────────────────────────────────────────────────────────────────┐
│                     Raw Socket (PF_PACKET)                     │
│                   Direct Network Interface                     │
└─────────────────────────────────────────────────────────────────┘
```

## 🚀 Installation & Usage

### Prerequisites
- Ruby 3.0+
- Linux operating system (for `PF_PACKET` support)
- Root privileges (for raw socket access)

### Quick Start

1. **Clone and setup:**
```bash
git clone https://github.com/your-username/RubyNetStack.git
cd RubyNetStack
bundle install
```

2. **Run the network stack:**
```bash
sudo ruby bin/server
```

3. **Test UDP echo server:**
```bash
# In another terminal
echo "hello world" | nc -u <your-ip> 4321
# Should return: "HELLO WORLD"
```

4. **Test ICMP ping:**
```bash
ping <configured-ip>
# Should receive automatic ping replies
```

### Configuration

Set environment variables to customize behavior:

```bash
# Enable debug mode (show hex dumps)
export RUBY_NET_STACK_DEBUG=1

# Enable packet analysis
export RUBY_NET_STACK_ANALYZE=1

# Enable checksum verification
export RUBY_NET_STACK_VERIFY_CHECKSUMS=1

# Configure network identity
export RUBY_NET_STACK_IP="192.168.1.100"
export RUBY_NET_STACK_MAC="02:42:ac:11:00:02"

# Run with configuration
sudo -E ruby bin/server eth0
```

## 🔧 Technical Implementation

### Raw Socket Creation
```ruby
# Create PF_PACKET socket for raw ethernet access
socket = Socket.open(Socket::PF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)

# Bind to specific network interface using sockaddr_ll
sockaddr_ll = [AF_PACKET, ETH_P_ALL, ifindex, 0, 0, 0, 0, 0, 0, 0, 0, 0].pack(\"SSISCC8\")
socket.bind(sockaddr_ll)
```

### Packet Parsing Pipeline
```ruby
# 1. Receive raw ethernet frame
data, _ = socket.recvfrom(65536)

# 2. Dispatch through protocol stack
result = packet_dispatcher.dispatch(data)

# 3. Route based on EtherType
case result[:frame].ethertype
when ETHERTYPE_IP   then parse_ip_packet(result[:frame].payload)
when ETHERTYPE_ARP  then parse_arp_packet(result[:frame].payload)
end
```

### Bit-Level Parsing Example
```ruby
# Parse IP header with bit manipulation
version_ihl = raw_data[0].unpack1(\"C\")
version = (version_ihl >> 4) & 0x0F  # Upper 4 bits
ihl = version_ihl & 0x0F            # Lower 4 bits

flags_frag = raw_data[6, 2].unpack1(\"n\")
flags = (flags_frag >> 13) & 0x07      # Upper 3 bits
fragment_offset = flags_frag & 0x1FFF  # Lower 13 bits
```

### Checksum Calculation (RFC 1071)
```ruby
def calculate_checksum(data)
  sum = 0
  
  # Sum 16-bit words
  (0...data.length).step(2) do |i|
    word = data[i, 2].unpack1(\"n\")
    sum += word
  end
  
  # Add carry bits
  while (sum >> 16) > 0
    sum = (sum & 0xFFFF) + (sum >> 16)
  end
  
  # Return one's complement
  (~sum) & 0xFFFF
end
```

## 📊 Packet Statistics

The stack provides real-time statistics:

```
Packet Statistics:
  Total: 1250
  Ethernet: 1250 (100.0%)
  IP: 892 (71.4%)
  ARP: 45 (3.6%)
  Unknown: 313 (25.0%)
  Invalid: 0 (0.0%)
```

## 🛡️ Security Considerations

- **Root Privileges**: Required for raw socket access
- **Network Exposure**: Responds to ARP and ICMP automatically
- **Packet Injection**: Can send arbitrary packets to the network
- **Educational Use**: Not intended for production environments

## 🧪 Testing & Development

### Protocol Testing
```bash
# Test ARP functionality
arping -c 1 <configured-ip>

# Test UDP echo server
echo "test" | nc -u <configured-ip> 4321

# Test ICMP responses  
ping -c 1 <configured-ip>

# Monitor with tcpdump
sudo tcpdump -i eth0 -v
```

### Debug Mode
```bash
# Enable maximum verbosity
export RUBY_NET_STACK_DEBUG=1
export RUBY_NET_STACK_ANALYZE=1
export RUBY_NET_STACK_VERIFY_CHECKSUMS=1

sudo -E ruby bin/server eth0
```

## 📁 Project Structure

```
RubyNetStack/
├── bin/
│   └── server              # Main executable
├── lib/
│   └── ruby_net_stack/
│       ├── raw_socket.rb       # Core socket management
│       ├── ethernet_frame.rb   # Layer 2 parsing
│       ├── ip_packet.rb        # Layer 3 parsing
│       ├── udp_datagram.rb     # Layer 4 UDP
│       ├── icmp_message.rb     # ICMP support
│       ├── arp_packet.rb       # ARP protocol
│       ├── checksum.rb         # RFC 1071 checksums
│       ├── ip_address.rb       # IP utilities
│       ├── network_interface.rb # ioctl wrappers
│       ├── packet_dispatcher.rb # Protocol routing
│       └── hex_presenter.rb    # Debug utilities
└── README.md
```

## 📚 Learning Resources

This project demonstrates:
- **Network Protocol Internals**: Hands-on experience with packet structure
- **System Programming**: Raw sockets and `ioctl` system calls
- **Bit Manipulation**: Header parsing and flag extraction
- **Network Security**: Understanding packet injection and sniffing
- **Ruby Systems Programming**: Low-level programming in a high-level language

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## ⚠️ Disclaimer

This project is for educational purposes only. Use responsibly and only on networks you own or have explicit permission to test on. The authors are not responsible for any misuse or damage.

## 📄 License

MIT License - see LICENSE file for details.

## 🙏 Acknowledgments

- RFC 1071 (Internet Checksum)
- RFC 826 (Address Resolution Protocol)
- RFC 791 (Internet Protocol)
- Linux Kernel Documentation (PF_PACKET)
- Stevens, W. Richard - \"Unix Network Programming\"