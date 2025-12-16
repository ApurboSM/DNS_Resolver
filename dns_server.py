#!/usr/bin/env python3
"""
Task 24: Recursive DNS Server
Performs recursive DNS resolution with caching and TTL handling.
"""

import socket
import time
import threading
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import random

from dns_protocol import (
    DNSMessage, DNSHeader, DNSQuestion, DNSResourceRecord,
    DNSType, DNSClass, DNSRcode, create_query, create_response
)


class CacheEntry:
    """DNS cache entry with TTL."""
    
    def __init__(self, records: List[DNSResourceRecord], timestamp: float):
        self.records = records
        self.timestamp = timestamp
    
    def is_expired(self) -> bool:
        """Check if entry has expired."""
        if not self.records:
            return True
        
        # Use minimum TTL
        min_ttl = min(record.ttl for record in self.records)
        age = time.time() - self.timestamp
        
        return age > min_ttl
    
    def get_remaining_ttl(self) -> int:
        """Get remaining TTL in seconds."""
        if not self.records:
            return 0
        
        min_ttl = min(record.ttl for record in self.records)
        age = int(time.time() - self.timestamp)
        remaining = min_ttl - age
        
        return max(0, remaining)


class DNSCache:
    """DNS response cache with TTL."""
    
    def __init__(self):
        self.cache: Dict[Tuple[str, int], CacheEntry] = {}
        self.lock = threading.Lock()
        self.hits = 0
        self.misses = 0
    
    def get(self, domain: str, qtype: int) -> Optional[List[DNSResourceRecord]]:
        """Get cached records."""
        with self.lock:
            key = (domain.lower(), qtype)
            
            if key in self.cache:
                entry = self.cache[key]
                
                if entry.is_expired():
                    del self.cache[key]
                    self.misses += 1
                    return None
                
                self.hits += 1
                
                # Update TTL to reflect remaining time
                remaining_ttl = entry.get_remaining_ttl()
                updated_records = []
                for record in entry.records:
                    updated_record = DNSResourceRecord(
                        record.name, record.rtype, record.rclass,
                        remaining_ttl, record.rdata
                    )
                    updated_records.append(updated_record)
                
                return updated_records
            
            self.misses += 1
            return None
    
    def put(self, domain: str, qtype: int, records: List[DNSResourceRecord]):
        """Cache records."""
        with self.lock:
            key = (domain.lower(), qtype)
            self.cache[key] = CacheEntry(records, time.time())
    
    def clear(self):
        """Clear cache."""
        with self.lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0
    
    def get_stats(self) -> dict:
        """Get cache statistics."""
        with self.lock:
            total = self.hits + self.misses
            hit_rate = (self.hits / total * 100) if total > 0 else 0
            
            return {
                'entries': len(self.cache),
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': hit_rate
            }


class RecursiveDNSServer:
    """Recursive DNS server."""
    
    # Root DNS servers (simplified - using Google's public DNS for simulation)
    ROOT_SERVERS = [
        ('8.8.8.8', 53),      # Google Public DNS
        ('1.1.1.1', 53),      # Cloudflare DNS
    ]
    
    def __init__(self, host: str = '0.0.0.0', port: int = 5353):
        self.host = host
        self.port = port
        self.cache = DNSCache()
        self.running = False
        self.socket = None
        
        # Statistics
        self.queries_received = 0
        self.queries_resolved = 0
        self.queries_failed = 0
    
    def start(self):
        """Start DNS server."""
        self.running = True
        
        # Create UDP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        
        print("="*70)
        print(f"{'Recursive DNS Server Started':^70}")
        print("="*70)
        print(f"Listening on: {self.host}:{self.port}")
        print(f"Cache: Enabled with TTL")
        print("="*70)
        print()
        
        # Start statistics thread
        threading.Thread(target=self.statistics_loop, daemon=True).start()
        
        # Handle queries
        while self.running:
            try:
                data, addr = self.socket.recvfrom(512)  # DNS messages max 512 bytes (UDP)
                
                # Handle in separate thread
                threading.Thread(
                    target=self.handle_query,
                    args=(data, addr),
                    daemon=True
                ).start()
                
            except Exception as e:
                if self.running:
                    print(f"[ERROR] Receive error: {e}")
    
    def handle_query(self, data: bytes, addr: Tuple[str, int]):
        """Handle DNS query."""
        try:
            # Parse query
            query = DNSMessage.from_bytes(data)
            self.queries_received += 1
            
            if not query.questions:
                return
            
            question = query.questions[0]
            domain = question.qname
            qtype = question.qtype
            
            print(f"[QUERY] {domain} (type={qtype}) from {addr[0]}:{addr[1]}")
            
            # Check cache
            cached_records = self.cache.get(domain, qtype)
            
            if cached_records:
                print(f"[CACHE] Hit for {domain} (type={qtype})")
                response = create_response(query, cached_records)
                self.socket.sendto(response.to_bytes(), addr)
                self.queries_resolved += 1
                return
            
            print(f"[CACHE] Miss for {domain} (type={qtype})")
            
            # Perform recursive resolution
            answers = self.resolve_recursive(domain, qtype)
            
            if answers:
                # Cache results
                self.cache.put(domain, qtype, answers)
                
                # Send response
                response = create_response(query, answers)
                self.socket.sendto(response.to_bytes(), addr)
                
                # Log results
                for answer in answers:
                    ip = answer.get_ip_address()
                    if ip:
                        print(f"[RESOLVED] {domain} -> {ip} (TTL={answer.ttl}s)")
                
                self.queries_resolved += 1
            else:
                # Send NXDOMAIN response
                response = create_response(query, [])
                response.header.rcode = DNSRcode.NXDOMAIN
                self.socket.sendto(response.to_bytes(), addr)
                
                print(f"[NXDOMAIN] {domain}")
                self.queries_failed += 1
                
        except Exception as e:
            print(f"[ERROR] Query handler error: {e}")
            self.queries_failed += 1
    
    def resolve_recursive(self, domain: str, qtype: int, depth: int = 0, max_depth: int = 10) -> List[DNSResourceRecord]:
        """
        Perform recursive DNS resolution.
        In a real implementation, this would query root -> TLD -> authoritative.
        For simplicity, we query upstream DNS servers directly.
        """
        if depth > max_depth:
            print(f"[ERROR] Max recursion depth reached for {domain}")
            return []
        
        # Try root/upstream servers
        for nameserver, port in self.ROOT_SERVERS:
            try:
                answers = self.query_nameserver(nameserver, port, domain, qtype)
                
                if answers:
                    # Check for CNAME
                    cname_record = None
                    for answer in answers:
                        if answer.rtype == DNSType.CNAME:
                            cname_record = answer
                            break
                    
                    if cname_record:
                        # Resolve CNAME
                        cname = cname_record.get_cname(b'')
                        if cname and cname != domain:
                            print(f"[CNAME] {domain} -> {cname}")
                            
                            # Recursively resolve CNAME
                            cname_answers = self.resolve_recursive(cname, qtype, depth + 1)
                            
                            # Return both CNAME and final answers
                            return [cname_record] + cname_answers
                    
                    return answers
                
            except Exception as e:
                print(f"[WARNING] Query to {nameserver} failed: {e}")
                continue
        
        return []
    
    def query_nameserver(self, nameserver: str, port: int, domain: str, qtype: int) -> List[DNSResourceRecord]:
        """Query a nameserver."""
        try:
            # Create query
            query = create_query(domain, qtype)
            query_data = query.to_bytes()
            
            # Send query via UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            
            sock.sendto(query_data, (nameserver, port))
            
            # Receive response
            response_data, _ = sock.recvfrom(512)
            sock.close()
            
            # Parse response
            response = DNSMessage.from_bytes(response_data)
            
            # Check response code
            if response.header.rcode != DNSRcode.NOERROR:
                return []
            
            return response.answers
            
        except socket.timeout:
            return []
        except Exception as e:
            raise e
    
    def statistics_loop(self):
        """Print statistics periodically."""
        while self.running:
            time.sleep(30)
            
            cache_stats = self.cache.get_stats()
            
            print(f"\n{'='*70}")
            print(f"{'DNS Server Statistics':^70}")
            print(f"{'='*70}")
            print(f"Queries Received: {self.queries_received}")
            print(f"Queries Resolved: {self.queries_resolved}")
            print(f"Queries Failed:   {self.queries_failed}")
            print(f"")
            print(f"Cache Entries:    {cache_stats['entries']}")
            print(f"Cache Hits:       {cache_stats['hits']}")
            print(f"Cache Misses:     {cache_stats['misses']}")
            print(f"Cache Hit Rate:   {cache_stats['hit_rate']:.1f}%")
            print(f"{'='*70}\n")
    
    def stop(self):
        """Stop DNS server."""
        self.running = False
        if self.socket:
            self.socket.close()


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Recursive DNS Server')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Server host')
    parser.add_argument('--port', type=int, default=5353, help='Server port (default: 5353)')
    parser.add_argument('--clear-cache', action='store_true', help='Start with empty cache')
    
    args = parser.parse_args()
    
    server = RecursiveDNSServer(args.host, args.port)
    
    if args.clear_cache:
        server.cache.clear()
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down DNS server...")
        server.stop()


if __name__ == '__main__':
    main()
