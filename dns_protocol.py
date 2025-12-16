#!/usr/bin/env python3
"""
Task 24: DNS Protocol Implementation
Low-level binary DNS protocol (RFC 1035) implementation.
"""

import struct
import socket
from typing import List, Tuple, Optional
from enum import IntEnum


class DNSType(IntEnum):
    """DNS record types."""
    A = 1       # IPv4 address
    NS = 2      # Nameserver
    CNAME = 5   # Canonical name
    SOA = 6     # Start of authority
    PTR = 12    # Pointer record
    MX = 15     # Mail exchange
    TXT = 16    # Text record
    AAAA = 28   # IPv6 address


class DNSClass(IntEnum):
    """DNS classes."""
    IN = 1      # Internet


class DNSOpcode(IntEnum):
    """DNS opcodes."""
    QUERY = 0
    IQUERY = 1
    STATUS = 2


class DNSRcode(IntEnum):
    """DNS response codes."""
    NOERROR = 0     # No error
    FORMERR = 1     # Format error
    SERVFAIL = 2    # Server failure
    NXDOMAIN = 3    # Name error (domain doesn't exist)
    NOTIMP = 4      # Not implemented
    REFUSED = 5     # Query refused


class DNSHeader:
    """DNS message header (12 bytes)."""
    
    def __init__(self):
        self.id = 0                # 16-bit identifier
        self.qr = 0                # Query/Response flag (0=query, 1=response)
        self.opcode = 0            # Operation code
        self.aa = 0                # Authoritative answer
        self.tc = 0                # Truncation
        self.rd = 1                # Recursion desired
        self.ra = 0                # Recursion available
        self.z = 0                 # Reserved
        self.rcode = 0             # Response code
        self.qdcount = 0           # Question count
        self.ancount = 0           # Answer count
        self.nscount = 0           # Authority count
        self.arcount = 0           # Additional count
    
    def to_bytes(self) -> bytes:
        """Serialize header to bytes."""
        # Flags byte 1: QR(1) | Opcode(4) | AA(1) | TC(1) | RD(1)
        flags1 = (self.qr << 7) | (self.opcode << 3) | (self.aa << 2) | (self.tc << 1) | self.rd
        
        # Flags byte 2: RA(1) | Z(3) | RCODE(4)
        flags2 = (self.ra << 7) | (self.z << 4) | self.rcode
        
        return struct.pack('!HBBHHHH',
                          self.id,
                          flags1,
                          flags2,
                          self.qdcount,
                          self.ancount,
                          self.nscount,
                          self.arcount)
    
    @staticmethod
    def from_bytes(data: bytes) -> 'DNSHeader':
        """Deserialize header from bytes."""
        header = DNSHeader()
        
        values = struct.unpack('!HBBHHHH', data[:12])
        header.id = values[0]
        
        flags1 = values[1]
        flags2 = values[2]
        
        # Parse flags
        header.qr = (flags1 >> 7) & 0x1
        header.opcode = (flags1 >> 3) & 0xF
        header.aa = (flags1 >> 2) & 0x1
        header.tc = (flags1 >> 1) & 0x1
        header.rd = flags1 & 0x1
        
        header.ra = (flags2 >> 7) & 0x1
        header.z = (flags2 >> 4) & 0x7
        header.rcode = flags2 & 0xF
        
        header.qdcount = values[3]
        header.ancount = values[4]
        header.nscount = values[5]
        header.arcount = values[6]
        
        return header
    
    def __repr__(self):
        return (f"DNSHeader(id={self.id}, qr={self.qr}, opcode={self.opcode}, "
                f"aa={self.aa}, tc={self.tc}, rd={self.rd}, ra={self.ra}, "
                f"rcode={self.rcode}, questions={self.qdcount}, "
                f"answers={self.ancount}, authority={self.nscount}, "
                f"additional={self.arcount})")


class DNSQuestion:
    """DNS question."""
    
    def __init__(self, qname: str = '', qtype: int = DNSType.A, qclass: int = DNSClass.IN):
        self.qname = qname      # Domain name
        self.qtype = qtype      # Query type
        self.qclass = qclass    # Query class
    
    def to_bytes(self) -> bytes:
        """Serialize question to bytes."""
        # Encode domain name
        name_bytes = encode_domain_name(self.qname)
        
        # Pack type and class
        question_bytes = name_bytes + struct.pack('!HH', self.qtype, self.qclass)
        
        return question_bytes
    
    @staticmethod
    def from_bytes(data: bytes, offset: int) -> Tuple['DNSQuestion', int]:
        """Deserialize question from bytes."""
        # Decode domain name
        qname, new_offset = decode_domain_name(data, offset)
        
        # Unpack type and class
        qtype, qclass = struct.unpack('!HH', data[new_offset:new_offset+4])
        new_offset += 4
        
        question = DNSQuestion(qname, qtype, qclass)
        return question, new_offset
    
    def __repr__(self):
        return f"DNSQuestion(name={self.qname}, type={self.qtype}, class={self.qclass})"


class DNSResourceRecord:
    """DNS resource record."""
    
    def __init__(self, name: str = '', rtype: int = DNSType.A, rclass: int = DNSClass.IN,
                 ttl: int = 0, rdata: bytes = b''):
        self.name = name        # Domain name
        self.rtype = rtype      # Record type
        self.rclass = rclass    # Record class
        self.ttl = ttl          # Time to live
        self.rdlength = len(rdata)  # Data length
        self.rdata = rdata      # Record data
    
    def to_bytes(self) -> bytes:
        """Serialize resource record to bytes."""
        # Encode domain name
        name_bytes = encode_domain_name(self.name)
        
        # Pack record fields
        record_bytes = name_bytes + struct.pack('!HHIH',
                                                 self.rtype,
                                                 self.rclass,
                                                 self.ttl,
                                                 self.rdlength)
        record_bytes += self.rdata
        
        return record_bytes
    
    @staticmethod
    def from_bytes(data: bytes, offset: int) -> Tuple['DNSResourceRecord', int]:
        """Deserialize resource record from bytes."""
        # Decode domain name
        name, new_offset = decode_domain_name(data, offset)
        
        # Unpack record fields
        rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[new_offset:new_offset+10])
        new_offset += 10
        
        # Extract rdata
        rdata = data[new_offset:new_offset+rdlength]
        new_offset += rdlength
        
        record = DNSResourceRecord(name, rtype, rclass, ttl, rdata)
        return record, new_offset
    
    def get_ip_address(self) -> Optional[str]:
        """Get IP address from A or AAAA record."""
        if self.rtype == DNSType.A and len(self.rdata) == 4:
            # IPv4
            return socket.inet_ntoa(self.rdata)
        elif self.rtype == DNSType.AAAA and len(self.rdata) == 16:
            # IPv6
            return socket.inet_ntop(socket.AF_INET6, self.rdata)
        return None
    
    def get_cname(self, data: bytes) -> Optional[str]:
        """Get CNAME from record."""
        if self.rtype == DNSType.CNAME:
            # CNAME rdata contains a domain name
            # Find offset of this record in original data
            # For simplicity, decode from rdata directly
            try:
                cname, _ = decode_domain_name_simple(self.rdata, 0)
                return cname
            except:
                return None
        return None
    
    def get_nameserver(self) -> Optional[str]:
        """Get nameserver from NS record."""
        if self.rtype == DNSType.NS:
            try:
                ns, _ = decode_domain_name_simple(self.rdata, 0)
                return ns
            except:
                return None
        return None
    
    def __repr__(self):
        ip = self.get_ip_address()
        if ip:
            return f"DNSResourceRecord(name={self.name}, type={self.rtype}, ttl={self.ttl}, ip={ip})"
        return f"DNSResourceRecord(name={self.name}, type={self.rtype}, ttl={self.ttl}, rdlength={self.rdlength})"


class DNSMessage:
    """Complete DNS message."""
    
    def __init__(self):
        self.header = DNSHeader()
        self.questions: List[DNSQuestion] = []
        self.answers: List[DNSResourceRecord] = []
        self.authority: List[DNSResourceRecord] = []
        self.additional: List[DNSResourceRecord] = []
    
    def to_bytes(self) -> bytes:
        """Serialize message to bytes."""
        # Update counts
        self.header.qdcount = len(self.questions)
        self.header.ancount = len(self.answers)
        self.header.nscount = len(self.authority)
        self.header.arcount = len(self.additional)
        
        # Serialize header
        data = self.header.to_bytes()
        
        # Serialize sections
        for question in self.questions:
            data += question.to_bytes()
        
        for answer in self.answers:
            data += answer.to_bytes()
        
        for auth in self.authority:
            data += auth.to_bytes()
        
        for add in self.additional:
            data += add.to_bytes()
        
        return data
    
    @staticmethod
    def from_bytes(data: bytes) -> 'DNSMessage':
        """Deserialize message from bytes."""
        message = DNSMessage()
        
        # Parse header
        message.header = DNSHeader.from_bytes(data)
        
        offset = 12  # Header is 12 bytes
        
        # Parse questions
        for _ in range(message.header.qdcount):
            question, offset = DNSQuestion.from_bytes(data, offset)
            message.questions.append(question)
        
        # Parse answers
        for _ in range(message.header.ancount):
            answer, offset = DNSResourceRecord.from_bytes(data, offset)
            message.answers.append(answer)
        
        # Parse authority
        for _ in range(message.header.nscount):
            auth, offset = DNSResourceRecord.from_bytes(data, offset)
            message.authority.append(auth)
        
        # Parse additional
        for _ in range(message.header.arcount):
            add, offset = DNSResourceRecord.from_bytes(data, offset)
            message.additional.append(add)
        
        return message
    
    def __repr__(self):
        return (f"DNSMessage(\n  header={self.header},\n"
                f"  questions={self.questions},\n"
                f"  answers={self.answers},\n"
                f"  authority={self.authority},\n"
                f"  additional={self.additional}\n)")


def encode_domain_name(domain: str) -> bytes:
    """
    Encode domain name to DNS wire format.
    Example: "www.example.com" -> \x03www\x07example\x03com\x00
    """
    if not domain:
        return b'\x00'
    
    parts = domain.split('.')
    encoded = b''
    
    for part in parts:
        if part:
            encoded += bytes([len(part)]) + part.encode('ascii')
    
    encoded += b'\x00'  # Null terminator
    return encoded


def decode_domain_name(data: bytes, offset: int) -> Tuple[str, int]:
    """
    Decode domain name from DNS wire format.
    Handles DNS message compression (pointer format).
    """
    parts = []
    jumped = False
    original_offset = offset
    jumps = 0
    max_jumps = 10  # Prevent infinite loops
    
    while True:
        if jumps > max_jumps:
            raise ValueError("Too many compression jumps")
        
        if offset >= len(data):
            raise ValueError("Offset beyond data length")
        
        length = data[offset]
        
        # Check for compression pointer (top 2 bits set)
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            
            # Pointer: next byte contains offset
            if offset + 1 >= len(data):
                raise ValueError("Invalid compression pointer")
            
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset = pointer
            jumped = True
            jumps += 1
            continue
        
        offset += 1
        
        # End of name
        if length == 0:
            break
        
        # Read label
        if offset + length > len(data):
            raise ValueError("Label extends beyond data")
        
        part = data[offset:offset+length].decode('ascii')
        parts.append(part)
        offset += length
    
    domain = '.'.join(parts)
    
    if not jumped:
        original_offset = offset
    
    return domain, original_offset


def decode_domain_name_simple(data: bytes, offset: int) -> Tuple[str, int]:
    """
    Simple domain name decoder without compression support.
    Used for CNAME/NS rdata parsing.
    """
    parts = []
    
    while True:
        if offset >= len(data):
            break
        
        length = data[offset]
        offset += 1
        
        if length == 0:
            break
        
        if offset + length > len(data):
            break
        
        part = data[offset:offset+length].decode('ascii', errors='ignore')
        parts.append(part)
        offset += length
    
    return '.'.join(parts), offset


def create_query(domain: str, qtype: int = DNSType.A, qid: int = None) -> DNSMessage:
    """Create a DNS query message."""
    import random
    
    message = DNSMessage()
    
    # Set header
    message.header.id = qid if qid is not None else random.randint(0, 65535)
    message.header.qr = 0  # Query
    message.header.opcode = DNSOpcode.QUERY
    message.header.rd = 1  # Recursion desired
    
    # Add question
    question = DNSQuestion(domain, qtype, DNSClass.IN)
    message.questions.append(question)
    
    return message


def create_response(query: DNSMessage, answers: List[DNSResourceRecord]) -> DNSMessage:
    """Create a DNS response message."""
    response = DNSMessage()
    
    # Copy header
    response.header.id = query.header.id
    response.header.qr = 1  # Response
    response.header.opcode = query.header.opcode
    response.header.rd = query.header.rd
    response.header.ra = 1  # Recursion available
    response.header.rcode = DNSRcode.NOERROR
    
    # Copy questions
    response.questions = query.questions.copy()
    
    # Add answers
    response.answers = answers
    
    return response


if __name__ == '__main__':
    # Test DNS protocol
    print("Testing DNS Protocol Implementation")
    print("="*70)
    
    # Test 1: Create query
    print("\n1. Creating DNS query for www.example.com")
    query = create_query("www.example.com", DNSType.A, qid=12345)
    query_bytes = query.to_bytes()
    print(f"   Query size: {len(query_bytes)} bytes")
    print(f"   Header: {query.header}")
    print(f"   Question: {query.questions[0]}")
    
    # Test 2: Parse query
    print("\n2. Parsing query back")
    parsed_query = DNSMessage.from_bytes(query_bytes)
    print(f"   Header: {parsed_query.header}")
    print(f"   Question: {parsed_query.questions[0]}")
    
    # Test 3: Create response with A record
    print("\n3. Creating DNS response with A record")
    ip_bytes = socket.inet_aton("93.184.216.34")  # example.com IP
    answer = DNSResourceRecord("www.example.com", DNSType.A, DNSClass.IN, 
                                ttl=3600, rdata=ip_bytes)
    response = create_response(query, [answer])
    response_bytes = response.to_bytes()
    print(f"   Response size: {len(response_bytes)} bytes")
    print(f"   Answer: {response.answers[0]}")
    print(f"   IP: {response.answers[0].get_ip_address()}")
    
    # Test 4: Domain name encoding/decoding
    print("\n4. Testing domain name encoding")
    test_domains = ["example.com", "www.google.com", "sub.domain.example.org"]
    for domain in test_domains:
        encoded = encode_domain_name(domain)
        decoded, _ = decode_domain_name(encoded, 0)
        print(f"   {domain} -> {len(encoded)} bytes -> {decoded}")
        assert domain == decoded, f"Mismatch: {domain} != {decoded}"
    
    print("\n" + "="*70)
    print("All tests passed!")
