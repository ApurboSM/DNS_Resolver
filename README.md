# DNS Resolver with Recursive Resolution

## Overview
Advanced DNS resolver implementing the binary DNS protocol (RFC 1035) with recursive resolution, caching, and CNAME handling. This is a low-level implementation demonstrating binary protocol design, bit-field manipulation, and domain name compression.

## Architecture

### Components
1. **dns_protocol.py** - Binary DNS protocol implementation (RFC 1035)
2. **dns_server.py** - Recursive DNS server with TTL-based caching
3. **dns_client.py** - Command-line DNS client

### DNS Protocol Details

#### Message Format
```
DNS Message (12-byte header + variable sections):
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|  Opcode   |AA|TC|RD|RA| Z|   RCODE        |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  Questions                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   Answers                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  Authority                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  Additional                   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

#### Header Fields
- **ID** (16 bits): Query identifier for matching responses
- **QR** (1 bit): Query (0) or Response (1)
- **Opcode** (4 bits): Query type (0 = standard query)
- **AA** (1 bit): Authoritative Answer
- **TC** (1 bit): Truncation (message exceeded 512 bytes)
- **RD** (1 bit): Recursion Desired
- **RA** (1 bit): Recursion Available
- **Z** (3 bits): Reserved (must be 0)
- **RCODE** (4 bits): Response code (0 = no error, 3 = name error)

#### Domain Name Encoding
Domain names use label-based encoding:
```
"www.example.com" → \x03www\x07example\x03com\x00

Format: [length][label][length][label]...\x00
- Length byte: Number of characters in label (1-63)
- Label: ASCII characters
- Null terminator: \x00
```

#### Domain Name Compression
To reduce message size, domain names can use pointers:
```
Compression Pointer: 0xC0 [offset]
- First 2 bits: 11 (0xC0)
- Remaining 14 bits: Offset into message where name begins

Example:
Position 12: \x03www\x07example\x03com\x00
Position 50: \xC0\x0C (pointer to position 12)
```

#### Record Types
```python
A     = 1   # IPv4 address (32 bits)
NS    = 2   # Nameserver
CNAME = 5   # Canonical name (alias)
SOA   = 6   # Start of authority
PTR   = 12  # Pointer record
MX    = 15  # Mail exchange
TXT   = 16  # Text record
AAAA  = 28  # IPv6 address (128 bits)
```

### Server Features

#### Recursive Resolution Flow
```
Client Query: www.example.com (A)
    ↓
Server Cache Check
    ↓ (miss)
Query Upstream (8.8.8.8 or 1.1.1.1)
    ↓
Receive Answer
    ↓
Check for CNAME
    ↓ (CNAME found: example.com)
Recursively Resolve example.com (A)
    ↓
Return: [CNAME record] + [A record]
    ↓
Cache Results with TTL
    ↓
Send Response to Client
```

**Note**: This simplified implementation queries public DNS servers (8.8.8.8, 1.1.1.1) directly. A production implementation would:
1. Query root nameservers (a.root-servers.net, etc.) for TLD servers
2. Query TLD servers (.com, .org, etc.) for authoritative servers
3. Query authoritative servers for final answer

#### TTL-Based Caching
```python
Cache Entry:
- Records: List of resource records
- Timestamp: When cached
- TTL: Time-to-live in seconds

On Cache Hit:
remaining_ttl = original_ttl - (current_time - timestamp)
if remaining_ttl <= 0:
    cache_miss()  # Expired
else:
    return records with updated TTL
```

#### CNAME Resolution
When a CNAME record is encountered:
```python
# Initial query: alias.example.com (A)
1. Receive CNAME: alias.example.com → www.example.com
2. Recursively query: www.example.com (A)
3. Receive A record: www.example.com → 1.2.3.4
4. Return both: [CNAME] + [A record]
```

Depth limit prevents infinite loops (max 10 levels).

## Setup

### Prerequisites
```bash
Python 3.7+
No external dependencies (uses only standard library)
```

### Installation
```bash
cd task24
```

## Usage

### 1. Start DNS Server
```bash
python dns_server.py
```

Output:
```
========================================
Recursive DNS Server
========================================
Port: 5353
Upstream: 8.8.8.8:53, 1.1.1.1:53
Cache: Enabled
========================================

[2024-01-15 10:30:00] Server started on 0.0.0.0:5353
```

**Options:**
```bash
python dns_server.py --port 5353 --verbose
```

### 2. Query DNS (Simple)
```bash
python dns_client.py query google.com
```

Output:
```
Querying 127.0.0.1:5353 for google.com (A)
----------------------------------------------------------------------

Response Code: NOERROR (0)
Query Time: 45.23 ms

Answers:
  142.250.185.46 (TTL: 300s)
```

### 3. Query Different Types
```bash
# IPv4 address
python dns_client.py query google.com --type A

# IPv6 address
python dns_client.py query google.com --type AAAA

# Canonical name (alias)
python dns_client.py query www.google.com --type CNAME

# Nameservers
python dns_client.py query google.com --type NS

# Mail servers
python dns_client.py query google.com --type MX
```

### 4. Verbose Output
```bash
python dns_client.py query google.com --type A -v
```

Output:
```
Querying 127.0.0.1:5353 for google.com (A)
----------------------------------------------------------------------

Response Code: NOERROR (0)
Query Time: 45.23 ms

Header:
  ID: 12345
  Flags: QR=1 AA=0 TC=0 RD=1 RA=1
  Questions: 1
  Answers: 1
  Authority: 0
  Additional: 0

Questions:
  google.com (A)

Answers:
  google.com 300s A 142.250.185.46
```

### 5. Interactive Mode
```bash
python dns_client.py interactive
```

Output:
```
========================================
Interactive DNS Client
========================================
Server: 127.0.0.1:5353

Commands:
  <domain>          - Query A record
  <domain> <type>   - Query specific type (A, AAAA, CNAME, NS, MX)
  quit              - Exit
========================================

> google.com
> facebook.com AAAA
> www.amazon.com CNAME
> quit
```

### 6. Benchmark Mode
```bash
python dns_client.py benchmark --domains google.com facebook.com amazon.com --iterations 5
```

Output:
```
========================================
DNS Benchmark
========================================
Server: 127.0.0.1:5353
Type: A
Domains: 3
Iterations: 5
========================================

Iteration 1/5
  ✓ google.com: 45.23 ms
  ✓ facebook.com: 38.12 ms
  ✓ amazon.com: 52.67 ms

Iteration 2/5
  ✓ google.com: 1.23 ms (cached)
  ✓ facebook.com: 0.98 ms (cached)
  ✓ amazon.com: 1.45 ms (cached)

========================================
Results
========================================
Total Queries: 15
Successful: 15
Failed: 0
Average Query Time: 15.42 ms
========================================
```

### 7. Custom DNS Server
```bash
# Query Google's DNS
python dns_client.py query google.com --server 8.8.8.8 --port 53

# Query Cloudflare's DNS
python dns_client.py query google.com --server 1.1.1.1 --port 53
```

## Testing Scenarios

### Test 1: Basic A Record Resolution
```bash
python dns_client.py query google.com --type A
```

**Expected**: IPv4 address (e.g., 142.250.185.46)

### Test 2: CNAME Following
```bash
python dns_client.py query www.github.com --type A -v
```

**Expected**:
- CNAME record: www.github.com → github.com
- A record: github.com → 140.82.121.4

### Test 3: Cache Hit Performance
```bash
# First query (cache miss)
python dns_client.py query amazon.com

# Second query (cache hit - should be much faster)
python dns_client.py query amazon.com
```

**Expected**:
- First query: ~50ms (upstream query)
- Second query: <2ms (cache hit)

### Test 4: IPv6 Resolution
```bash
python dns_client.py query google.com --type AAAA
```

**Expected**: IPv6 address (e.g., 2607:f8b0:4004:c07::65)

### Test 5: Nameserver Discovery
```bash
python dns_client.py query google.com --type NS -v
```

**Expected**: List of nameservers (e.g., ns1.google.com, ns2.google.com)

### Test 6: TTL Expiration
```bash
# Query domain
python dns_client.py query example.com

# Wait for TTL to expire (check TTL value in response)
# Query again - should perform upstream lookup
python dns_client.py query example.com
```

## Server Statistics

The server prints statistics every 30 seconds:

```
========================================
DNS Server Statistics
========================================
Uptime: 120 seconds
Queries Received: 150
Queries Resolved: 148
Queries Failed: 2
Cache Hit Rate: 65.33% (98/150)
========================================
```

## Protocol Implementation Details

### Binary Encoding (dns_protocol.py)

#### Header Bitfield Packing
```python
# Pack flags into 2 bytes
flags1 = (qr << 7) | (opcode << 3) | (aa << 2) | (tc << 1) | rd
flags2 = (ra << 7) | (z << 4) | rcode

# Pack entire header (12 bytes, network byte order)
struct.pack('!HBBHHHH', id, flags1, flags2, qdcount, ancount, nscount, arcount)
```

#### Domain Name Encoding
```python
def encode_domain_name(name: str) -> bytes:
    """Encode domain name in DNS format."""
    data = b''
    for label in name.split('.'):
        if label:
            data += bytes([len(label)]) + label.encode('ascii')
    data += b'\x00'  # Null terminator
    return data
```

#### Compression Pointer Detection
```python
def decode_domain_name(data: bytes, offset: int) -> tuple:
    """Decode domain name, handling compression pointers."""
    labels = []
    jumped = False
    original_offset = offset
    jumps = 0
    
    while True:
        length = data[offset]
        
        # Check for compression pointer (11xxxxxx xxxxxxxx)
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
                jumped = True
            
            # Extract pointer offset
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset = pointer
            
            jumps += 1
            if jumps > 10:  # Prevent infinite loops
                raise ValueError("Too many compression jumps")
        
        elif length == 0:
            break
        
        else:
            offset += 1
            label = data[offset:offset + length].decode('ascii')
            labels.append(label)
            offset += length
    
    name = '.'.join(labels)
    final_offset = original_offset if jumped else offset + 1
    
    return name, final_offset
```

### Resource Record Parsing

#### A Record (IPv4)
```python
def get_ip_address(self) -> Optional[str]:
    """Get IP address from A or AAAA record."""
    if self.rtype == DNSType.A and len(self.rdata) == 4:
        return socket.inet_ntoa(self.rdata)
    elif self.rtype == DNSType.AAAA and len(self.rdata) == 16:
        return socket.inet_ntop(socket.AF_INET6, self.rdata)
    return None
```

#### CNAME Record
```python
def get_cname(self, message_data: bytes) -> Optional[str]:
    """Get canonical name from CNAME record."""
    if self.rtype == DNSType.CNAME:
        cname, _ = decode_domain_name(self.rdata, 0)
        return cname
    return None
```

## Comparison with Production DNS

### This Implementation
- ✓ Binary DNS protocol (RFC 1035)
- ✓ Recursive resolution
- ✓ TTL-based caching
- ✓ CNAME following
- ✓ A/AAAA/CNAME/NS records
- ✓ Domain name compression
- ✓ UDP transport
- ✗ Queries public DNS directly (simplified)
- ✗ No DNSSEC validation
- ✗ No TCP fallback
- ✗ No negative caching

### Production DNS (BIND, Unbound)
- Full RFC 1035 compliance
- Query root → TLD → authoritative servers
- DNSSEC validation
- TCP fallback for large responses
- Negative caching (NXDOMAIN)
- Zone transfers (AXFR)
- Dynamic updates
- Rate limiting
- Access control lists

## Known Limitations

1. **Simplified Resolution**: Queries public DNS (8.8.8.8, 1.1.1.1) instead of root servers
   - Real implementation would query root servers, then TLD servers, then authoritative
   - This simplification makes the code more understandable

2. **No TCP Fallback**: Only UDP supported
   - DNS uses TCP for responses > 512 bytes
   - Production servers should support both

3. **No DNSSEC**: No cryptographic validation
   - DNSSEC adds signatures to DNS records
   - Prevents cache poisoning attacks

4. **Limited Record Types**: Only A, AAAA, CNAME, NS, MX, TXT
   - Full DNS has 40+ record types

5. **Simple Cache Eviction**: Expires based on TTL only
   - Production caches use LRU, memory limits

## Future Enhancements

1. **Real Recursive Resolution**
   - Query root servers (a-m.root-servers.net)
   - Follow referrals to TLD servers
   - Query authoritative servers

2. **TCP Transport**
   - Fallback for large responses
   - Zone transfers

3. **DNSSEC Validation**
   - Verify signatures (RRSIG)
   - Chain of trust (DNSKEY, DS)

4. **Negative Caching**
   - Cache NXDOMAIN responses
   - Reduces upstream queries

5. **Advanced Cache**
   - LRU eviction
   - Memory limits
   - Pre-fetching popular domains

6. **More Record Types**
   - SRV (service discovery)
   - CAA (certificate authority)
   - TLSA (TLS authentication)

7. **Performance**
   - Connection pooling
   - Parallel upstream queries
   - Response pipelining

## Educational Value

This implementation demonstrates:

1. **Binary Protocol Design**
   - Bit-field manipulation
   - Network byte order (big-endian)
   - Struct packing/unpacking

2. **Domain Name Compression**
   - Pointer format (RFC 1035)
   - Offset calculation
   - Loop prevention

3. **Recursive Resolution**
   - Query chaining
   - CNAME following
   - Depth limits

4. **Cache Design**
   - TTL-based expiration
   - Thread-safe operations
   - Hit rate optimization

5. **UDP Programming**
   - Datagram sockets
   - Timeouts and retries
   - Message size limits

## Troubleshooting

### Server not starting
```bash
# Check if port 5353 is in use
netstat -an | findstr 5353

# Use different port
python dns_server.py --port 5454
```

### No response from server
```bash
# Check server logs
# Verify server is running
# Try different domain
python dns_client.py query 8.8.8.8 --type A
```

### Upstream query fails
```bash
# Check internet connection
# Try different upstream server
# Check firewall rules (UDP port 53)
```

### Cache not working
```bash
# Verify TTL in response
python dns_client.py query google.com -v

# Check server statistics
# Look for cache hit count
```

## References

- **RFC 1035**: Domain Names - Implementation and Specification
- **RFC 1034**: Domain Names - Concepts and Facilities
- **RFC 2181**: Clarifications to the DNS Specification
- **RFC 4033-4035**: DNS Security Extensions (DNSSEC)

## License

Educational purposes only. This is a simplified implementation for learning DNS internals.

## Authors

Socket Programming Lab - CSE421
