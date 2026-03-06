#!/usr/bin/env python3
import sys
import argparse
import dns.resolver
import concurrent.futures
from typing import List, Optional

def resolve_domain(domain: str, resolver: Optional[str] = None, record_type: str = 'A') -> dict:
    try:
        res = dns.resolver.Resolver()
        if resolver:
            res.nameservers = [resolver]
        
        answers = res.resolve(domain, record_type)
        return {
            'domain': domain,
            'record_type': record_type,
            'answers': [str(rdata) for rdata in answers],
            'status': 'success'
        }
    except Exception as e:
        return {
            'domain': domain,
            'record_type': record_type,
            'answers': [],
            'status': 'error',
            'error': str(e)
        }

def main():
    parser = argparse.ArgumentParser(description='Simple DNS resolver - massdns alternative')
    parser.add_argument('-d', '--domain', help='Single domain to resolve')
    parser.add_argument('-l', '--list', help='File containing list of domains')
    parser.add_argument('-t', '--type', default='A', help='DNS record type (default: A)')
    parser.add_argument('-r', '--resolver', help='DNS resolver to use')
    parser.add_argument('-c', '--concurrency', type=int, default=10, help='Number of concurrent threads')
    parser.add_argument('-o', '--output', help='Output file')
    
    args = parser.parse_args()
    
    domains = []
    if args.domain:
        domains.append(args.domain)
    elif args.list:
        with open(args.list, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    else:
        print("Error: Please provide either --domain or --list")
        sys.exit(1)
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = {executor.submit(resolve_domain, domain, args.resolver, args.type): domain for domain in domains}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            if result['status'] == 'success':
                print(f"{result['domain']} {result['record_type']} {', '.join(result['answers'])}")
            else:
                print(f"{result['domain']} ERROR {result.get('error', 'Unknown error')}")
    
    if args.output:
        with open(args.output, 'w') as f:
            for result in results:
                if result['status'] == 'success':
                    f.write(f"{result['domain']} {result['record_type']} {', '.join(result['answers'])}\n")

if __name__ == '__main__':
    main()
