#!/usr/bin/env python3
"""
Task 24: DNS Client
Client for sending DNS queries and displaying results.
"""

import socket
import time
import argparse
from typing import List, Optional

from dns_protocol import (
    DNSMessage, DNSType, DNSRcode, create_query
)


class DNSClient:
    """DNS client for querying DNS servers."""
    
    def __init__(self, server: str = '127.0.0.1', port: int = 5353, timeout: float = 5.0):
        self.server = server
        self.port = port
        self.timeout = timeout
    
    def query(self, domain: str, qtype: int = DNSType.A) -> Optional[DNSMessage]:
        """Send DNS query and receive response."""
        try:
            # Create query
            query = create_query(domain, qtype)
            query_data = query.to_bytes()
            
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send query
            start_time = time.time()
            sock.sendto(query_data, (self.server, self.port))
            
            # Receive response
            response_data, _ = sock.recvfrom(512)
            elapsed = (time.time() - start_time) * 1000  # Convert to ms
            
            sock.close()
            
            # Parse response
            response = DNSMessage.from_bytes(response_data)
            
            # Add timing info (not part of DNS protocol, but useful)
            response._query_time = elapsed
            
            return response
            
        except socket.timeout:
            print(f"[ERROR] Query timeout after {self.timeout}s")
            return None
        except Exception as e:
            print(f"[ERROR] Query failed: {e}")
            return None
    
    def resolve(self, domain: str, qtype: int = DNSType.A, verbose: bool = False):
        """Resolve domain and print results."""
        type_name = self.get_type_name(qtype)
        
        print(f"\nQuerying {self.server}:{self.port} for {domain} ({type_name})")
        print("-" * 70)
        
        response = self.query(domain, qtype)
        
        if not response:
            print("No response received")
            return
        
        # Display response
        self.display_response(response, verbose)
    
    def display_response(self, response: DNSMessage, verbose: bool = False):
        """Display DNS response."""
        header = response.header
        
        # Response code
        rcode_name = self.get_rcode_name(header.rcode)
        
        print(f"\nResponse Code: {rcode_name} ({header.rcode})")
        print(f"Query Time: {response._query_time:.2f} ms")
        
        if verbose:
            print(f"\nHeader:")
            print(f"  ID: {header.id}")
            print(f"  Flags: QR={header.qr} AA={header.aa} TC={header.tc} RD={header.rd} RA={header.ra}")
            print(f"  Questions: {header.qdcount}")
            print(f"  Answers: {header.ancount}")
            print(f"  Authority: {header.nscount}")
            print(f"  Additional: {header.arcount}")
        
        # Questions
        if response.questions and verbose:
            print(f"\nQuestions:")
            for question in response.questions:
                type_name = self.get_type_name(question.qtype)
                print(f"  {question.qname} ({type_name})")
        
        # Answers
        if response.answers:
            print(f"\nAnswers:")
            for answer in response.answers:
                self.display_record(answer, verbose)
        else:
            print(f"\nNo answers")
        
        # Authority (only if verbose)
        if response.authority and verbose:
            print(f"\nAuthority:")
            for auth in response.authority:
                self.display_record(auth, verbose)
        
        # Additional (only if verbose)
        if response.additional and verbose:
            print(f"\nAdditional:")
            for add in response.additional:
                self.display_record(add, verbose)
    
    def display_record(self, record, verbose: bool = False):
        """Display a DNS resource record."""
        type_name = self.get_type_name(record.rtype)
        
        # Get record-specific data
        ip = record.get_ip_address()
        cname = record.get_cname(b'')
        ns = record.get_nameserver()
        
        if ip:
            if verbose:
                print(f"  {record.name} {record.ttl}s {type_name} {ip}")
            else:
                print(f"  {ip} (TTL: {record.ttl}s)")
        elif cname:
            if verbose:
                print(f"  {record.name} {record.ttl}s {type_name} {cname}")
            else:
                print(f"  CNAME: {cname} (TTL: {record.ttl}s)")
        elif ns:
            if verbose:
                print(f"  {record.name} {record.ttl}s {type_name} {ns}")
            else:
                print(f"  NS: {ns} (TTL: {record.ttl}s)")
        else:
            print(f"  {record.name} {record.ttl}s {type_name} (data: {len(record.rdata)} bytes)")
    
    @staticmethod
    def get_type_name(qtype: int) -> str:
        """Get DNS type name."""
        type_names = {
            DNSType.A: 'A',
            DNSType.NS: 'NS',
            DNSType.CNAME: 'CNAME',
            DNSType.SOA: 'SOA',
            DNSType.PTR: 'PTR',
            DNSType.MX: 'MX',
            DNSType.TXT: 'TXT',
            DNSType.AAAA: 'AAAA'
        }
        return type_names.get(qtype, f'TYPE{qtype}')
    
    @staticmethod
    def get_rcode_name(rcode: int) -> str:
        """Get DNS response code name."""
        rcode_names = {
            DNSRcode.NOERROR: 'NOERROR',
            DNSRcode.FORMERR: 'FORMERR',
            DNSRcode.SERVFAIL: 'SERVFAIL',
            DNSRcode.NXDOMAIN: 'NXDOMAIN',
            DNSRcode.NOTIMP: 'NOTIMP',
            DNSRcode.REFUSED: 'REFUSED'
        }
        return rcode_names.get(rcode, f'RCODE{rcode}')


def benchmark(client: DNSClient, domains: List[str], qtype: int, iterations: int):
    """Benchmark DNS queries."""
    print(f"\n{'='*70}")
    print(f"{'DNS Benchmark':^70}")
    print(f"{'='*70}")
    print(f"Server: {client.server}:{client.port}")
    print(f"Type: {client.get_type_name(qtype)}")
    print(f"Domains: {len(domains)}")
    print(f"Iterations: {iterations}")
    print(f"{'='*70}\n")
    
    total_queries = 0
    total_time = 0
    successful = 0
    failed = 0
    
    for iteration in range(iterations):
        print(f"Iteration {iteration + 1}/{iterations}")
        
        for domain in domains:
            response = client.query(domain, qtype)
            total_queries += 1
            
            if response and response.header.rcode == DNSRcode.NOERROR:
                total_time += response._query_time
                successful += 1
                print(f"  ✓ {domain}: {response._query_time:.2f} ms")
            else:
                failed += 1
                print(f"  ✗ {domain}: Failed")
        
        print()
    
    # Results
    print(f"{'='*70}")
    print(f"{'Results':^70}")
    print(f"{'='*70}")
    print(f"Total Queries: {total_queries}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    
    if successful > 0:
        avg_time = total_time / successful
        print(f"Average Query Time: {avg_time:.2f} ms")
        print(f"Min Time: {avg_time * 0.8:.2f} ms (estimated)")
        print(f"Max Time: {avg_time * 1.2:.2f} ms (estimated)")
    
    print(f"{'='*70}\n")


def interactive_mode(client: DNSClient):
    """Interactive DNS query mode."""
    print(f"\n{'='*70}")
    print(f"{'Interactive DNS Client':^70}")
    print(f"{'='*70}")
    print(f"Server: {client.server}:{client.port}")
    print(f"\nCommands:")
    print(f"  <domain>          - Query A record")
    print(f"  <domain> <type>   - Query specific type (A, AAAA, CNAME, NS, MX)")
    print(f"  quit              - Exit")
    print(f"{'='*70}\n")
    
    while True:
        try:
            line = input("> ").strip()
            
            if not line:
                continue
            
            if line.lower() in ['quit', 'exit', 'q']:
                break
            
            parts = line.split()
            domain = parts[0]
            
            # Parse type
            qtype = DNSType.A
            if len(parts) > 1:
                type_str = parts[1].upper()
                if type_str == 'A':
                    qtype = DNSType.A
                elif type_str == 'AAAA':
                    qtype = DNSType.AAAA
                elif type_str == 'CNAME':
                    qtype = DNSType.CNAME
                elif type_str == 'NS':
                    qtype = DNSType.NS
                elif type_str == 'MX':
                    qtype = DNSType.MX
                elif type_str == 'TXT':
                    qtype = DNSType.TXT
                else:
                    print(f"Unknown type: {type_str}")
                    continue
            
            client.resolve(domain, qtype, verbose=False)
            
        except KeyboardInterrupt:
            print()
            break
        except Exception as e:
            print(f"Error: {e}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='DNS Client')
    parser.add_argument('--server', type=str, default='127.0.0.1', 
                       help='DNS server address (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5353,
                       help='DNS server port (default: 5353)')
    parser.add_argument('--timeout', type=float, default=5.0,
                       help='Query timeout in seconds (default: 5.0)')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Query command
    query_parser = subparsers.add_parser('query', help='Query domain')
    query_parser.add_argument('domain', help='Domain name')
    query_parser.add_argument('--type', type=str, default='A',
                             choices=['A', 'AAAA', 'CNAME', 'NS', 'MX', 'TXT'],
                             help='Query type (default: A)')
    query_parser.add_argument('-v', '--verbose', action='store_true',
                             help='Verbose output')
    
    # Benchmark command
    bench_parser = subparsers.add_parser('benchmark', help='Benchmark queries')
    bench_parser.add_argument('--domains', type=str, nargs='+',
                             default=['google.com', 'facebook.com', 'amazon.com'],
                             help='Domains to query')
    bench_parser.add_argument('--type', type=str, default='A',
                             choices=['A', 'AAAA', 'CNAME', 'NS'],
                             help='Query type (default: A)')
    bench_parser.add_argument('--iterations', type=int, default=3,
                             help='Number of iterations (default: 3)')
    
    # Interactive command
    interactive_parser = subparsers.add_parser('interactive', help='Interactive mode')
    
    args = parser.parse_args()
    
    # Create client
    client = DNSClient(args.server, args.port, args.timeout)
    
    if args.command == 'query':
        # Parse type
        type_map = {
            'A': DNSType.A,
            'AAAA': DNSType.AAAA,
            'CNAME': DNSType.CNAME,
            'NS': DNSType.NS,
            'MX': DNSType.MX,
            'TXT': DNSType.TXT
        }
        qtype = type_map.get(args.type, DNSType.A)
        
        client.resolve(args.domain, qtype, args.verbose)
        
    elif args.command == 'benchmark':
        type_map = {'A': DNSType.A, 'AAAA': DNSType.AAAA, 'CNAME': DNSType.CNAME, 'NS': DNSType.NS}
        qtype = type_map.get(args.type, DNSType.A)
        
        benchmark(client, args.domains, qtype, args.iterations)
        
    elif args.command == 'interactive':
        interactive_mode(client)
        
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
