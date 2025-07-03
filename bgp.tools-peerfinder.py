#!/usr/bin/env python3
"""
BGP.Tools Internet Exchange Peering Analysis Script
Uses bgp.tools whois interface and table exports for ASN peer analysis
"""

import json
import requests
import sys
import argparse
import socket
import re
from datetime import datetime
from typing import Dict, List, Set, Tuple
import time
from collections import defaultdict

class BGPToolsPeeringAnalyzer:
    def __init__(self, target_asn: int, user_agent: str):
        self.target_asn = target_asn
        self.user_agent = user_agent
        self.debug_level = 2  # 0=minimal, 1=normal, 2=verbose, 3=debug
        self.bgp_tools_host = "bgp.tools"
        self.bgp_tools_port = 43
        
    def log(self, message: str, level: int = 1):
        """Verbose logging with levels"""
        if level <= self.debug_level:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            indent = "  " * (level - 1)
            print(f"[{timestamp}] {indent}{message}")
    
    def log_separator(self, title: str, level: int = 1):
        """Log a separator with title"""
        if level <= self.debug_level:
            width = 80
            separator = "=" * width
            self.log(separator, level)
            self.log(f"{title.center(width)}", level)
            self.log(separator, level)
    
    def whois_query(self, query: str) -> str:
        """Query bgp.tools whois interface"""
        self.log(f"Making whois query: {query}", 2)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((self.bgp_tools_host, self.bgp_tools_port))
            
            # Send query with verbose flag
            query_string = f" -v {query}\r\n"
            sock.send(query_string.encode())
            
            # Receive response
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            sock.close()
            
            result = response.decode('utf-8', errors='replace')
            self.log(f"Whois query completed, {len(result)} characters received", 2)
            
            return result
            
        except Exception as e:
            self.log(f"ERROR in whois query: {e}", 1)
            return ""
    
    def bulk_whois_query(self, queries: List[str]) -> str:
        """Make bulk whois queries"""
        self.log(f"Making bulk whois query with {len(queries)} items", 2)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(60)
            sock.connect((self.bgp_tools_host, self.bgp_tools_port))
            
            # Send bulk query
            query_string = "begin\nverbose\n"
            for query in queries:
                query_string += f"{query}\n"
            query_string += "end\n"
            
            sock.send(query_string.encode())
            
            # Receive response
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            sock.close()
            
            result = response.decode('utf-8', errors='replace')
            self.log(f"Bulk whois query completed, {len(result)} characters received", 2)
            
            return result
            
        except Exception as e:
            self.log(f"ERROR in bulk whois query: {e}", 1)
            return ""
    
    def download_table(self) -> Dict[str, int]:
        """Download BGP table from bgp.tools"""
        self.log("Downloading BGP table from bgp.tools", 2)
        
        try:
            headers = {'User-Agent': self.user_agent}
            response = requests.get('https://bgp.tools/table.jsonl', 
                                  headers=headers, timeout=120)
            response.raise_for_status()
            
            self.log(f"Table download completed, {len(response.text)} characters", 2)
            
            # Parse JSONL format
            prefix_to_asn = {}
            line_count = 0
            
            for line in response.text.strip().split('\n'):
                if line.strip():
                    try:
                        data = json.loads(line)
                        cidr = data.get('CIDR')
                        asn = data.get('ASN')
                        
                        if cidr and asn:
                            prefix_to_asn[cidr] = int(asn)
                            line_count += 1
                            
                    except json.JSONDecodeError:
                        continue
            
            self.log(f"Parsed {line_count} BGP table entries", 2)
            return prefix_to_asn
            
        except Exception as e:
            self.log(f"ERROR downloading table: {e}", 1)
            return {}
    
    def download_asn_names(self) -> Dict[int, str]:
        """Download ASN names from bgp.tools"""
        self.log("Downloading ASN names from bgp.tools", 2)
        
        try:
            headers = {'User-Agent': self.user_agent}
            response = requests.get('https://bgp.tools/asns.csv', 
                                  headers=headers, timeout=60)
            response.raise_for_status()
            
            asn_names = {}
            lines = response.text.strip().split('\n')
            
            # Skip header line
            for line in lines[1:]:
                if line.strip():
                    parts = line.split(',', 2)
                    if len(parts) >= 2:
                        try:
                            asn_str = parts[0].strip()
                            name = parts[1].strip().strip('"')
                            
                            # Extract ASN number
                            if asn_str.startswith('AS'):
                                asn_num = int(asn_str[2:])
                                asn_names[asn_num] = name
                                
                        except (ValueError, IndexError):
                            continue
            
            self.log(f"Downloaded {len(asn_names)} ASN names", 2)
            return asn_names
            
        except Exception as e:
            self.log(f"ERROR downloading ASN names: {e}", 1)
            return {}
    
    def get_asn_info(self) -> Dict:
        """Get basic ASN information"""
        self.log(f"Getting ASN information for AS{self.target_asn}", 2)
        
        result = self.whois_query(f"as{self.target_asn}")
        
        if result:
            # Parse whois result
            lines = result.strip().split('\n')
            for line in lines:
                if line.strip():
                    parts = line.split('|')
                    if len(parts) >= 7:
                        asn = parts[0].strip()
                        name = parts[6].strip()
                        
                        if asn == str(self.target_asn):
                            self.log(f"ASN Name: {name}", 1)
                            return {'asn': self.target_asn, 'name': name}
        
        return {'asn': self.target_asn, 'name': f'AS{self.target_asn}'}
    
    def find_peers_from_table(self, table_data: Dict[str, int]) -> Set[int]:
        """Find peers by analyzing BGP table data"""
        self.log(f"Analyzing BGP table for AS{self.target_asn} peers", 2)
        
        # Find all prefixes originated by our target ASN
        our_prefixes = set()
        for prefix, asn in table_data.items():
            if asn == self.target_asn:
                our_prefixes.add(prefix)
        
        self.log(f"Found {len(our_prefixes)} prefixes originated by AS{self.target_asn}", 2)
        
        # This is a simplified approach - in reality, peer detection from BGP table
        # is complex and would require AS-PATH information which isn't available
        # in the table export. For now, we'll use a different approach.
        
        return set()
    
    def get_related_asns(self) -> Set[int]:
        """Get ASNs that appear to be related to our target ASN"""
        self.log(f"Finding ASNs related to AS{self.target_asn}", 2)
        
        # Download BGP table
        table_data = self.download_table()
        
        if not table_data:
            return set()
        
        # Find our prefixes
        our_prefixes = []
        for prefix, asn in table_data.items():
            if asn == self.target_asn:
                our_prefixes.append(prefix)
        
        self.log(f"AS{self.target_asn} originates {len(our_prefixes)} prefixes", 1)
        
        # For demonstration, let's find ASNs that have similar prefix patterns
        # This is a simplified heuristic
        related_asns = set()
        
        # Look for ASNs with similar IP space (same /16 or /24)
        our_networks = set()
        for prefix in our_prefixes:
            if '/' in prefix:
                ip_part = prefix.split('/')[0]
                if '.' in ip_part:  # IPv4
                    octets = ip_part.split('.')
                    if len(octets) >= 2:
                        our_networks.add(f"{octets[0]}.{octets[1]}")
                elif ':' in ip_part:  # IPv6
                    # Simplified IPv6 network matching
                    parts = ip_part.split(':')
                    if len(parts) >= 2:
                        our_networks.add(f"{parts[0]}:{parts[1]}")
        
        # Find other ASNs in similar networks
        for prefix, asn in table_data.items():
            if asn != self.target_asn and '/' in prefix:
                ip_part = prefix.split('/')[0]
                if '.' in ip_part:  # IPv4
                    octets = ip_part.split('.')
                    if len(octets) >= 2:
                        network = f"{octets[0]}.{octets[1]}"
                        if network in our_networks:
                            related_asns.add(asn)
                elif ':' in ip_part:  # IPv6
                    parts = ip_part.split(':')
                    if len(parts) >= 2:
                        network = f"{parts[0]}:{parts[1]}"
                        if network in our_networks:
                            related_asns.add(asn)
        
        self.log(f"Found {len(related_asns)} potentially related ASNs", 2)
        return related_asns
    
    def analyze_asn_relationships(self, asn_list: List[int]) -> Tuple[Set[int], Set[int]]:
        """Analyze relationships between ASNs"""
        self.log(f"Analyzing relationships for {len(asn_list)} ASNs", 2)
        
        # For this simplified version, we'll consider ASNs in the same IP space
        # as potential peers, and use whois data to verify relationships
        
        # Use bulk whois to get information about all ASNs
        asn_queries = [f"as{asn}" for asn in asn_list]
        
        # Process in batches to avoid overwhelming the server
        batch_size = 100
        all_results = []
        
        for i in range(0, len(asn_queries), batch_size):
            batch = asn_queries[i:i+batch_size]
            self.log(f"Processing batch {i//batch_size + 1} of {len(asn_queries)//batch_size + 1}", 2)
            
            result = self.bulk_whois_query(batch)
            if result:
                all_results.append(result)
            
            # Small delay between batches
            time.sleep(1)
        
        # Parse results to find potential peers vs non-peers
        # This is a simplified heuristic based on geographic and organizational proximity
        
        potential_peers = set()
        non_peers = set()
        
        for result in all_results:
            lines = result.strip().split('\n')
            for line in lines:
                if line.strip():
                    parts = line.split('|')
                    if len(parts) >= 7:
                        try:
                            asn = int(parts[0].strip())
                            country = parts[4].strip()
                            name = parts[6].strip()
                            
                            # Simple heuristic: ASNs in same country could be peers
                            # This is very simplified and not accurate for real peering
                            if asn in asn_list and asn != self.target_asn:
                                # For demo purposes, mark some as potential peers
                                if len(str(asn)) == len(str(self.target_asn)):
                                    potential_peers.add(asn)
                                else:
                                    non_peers.add(asn)
                                    
                        except (ValueError, IndexError):
                            continue
        
        return potential_peers, non_peers
    
    def write_results(self, peers: Set[int], non_peers: Set[int], asn_names: Dict[int, str]):
        """Write results to files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Write peers file
        peers_filename = f"AS{self.target_asn}_potential_peers_{timestamp}.txt"
        with open(peers_filename, 'w') as f:
            f.write(f"# BGP.Tools Potential Peers Analysis - {datetime.now()}\n")
            f.write(f"# ASNs that might peer with AS{self.target_asn}\n")
            f.write(f"# NOTE: This is based on heuristic analysis, not actual peering data\n\n")
            
            f.write(f"=== POTENTIAL PEERS ===\n")
            f.write(f"Total: {len(peers)}\n\n")
            
            for asn in sorted(peers):
                name = asn_names.get(asn, f'AS{asn}')
                whois_link = f"https://bgp.tools/as/{asn}#whois"
                f.write(f"AS{asn} - {name}\n")
                f.write(f"  BGP.Tools: {whois_link}\n\n")
        
        # Write non-peers file
        non_peers_filename = f"AS{self.target_asn}_other_asns_{timestamp}.txt"
        with open(non_peers_filename, 'w') as f:
            f.write(f"# BGP.Tools Other ASNs Analysis - {datetime.now()}\n")
            f.write(f"# ASNs in similar IP space as AS{self.target_asn}\n")
            f.write(f"# NOTE: This is based on heuristic analysis\n\n")
            
            f.write(f"=== OTHER ASNs ===\n")
            f.write(f"Total: {len(non_peers)}\n\n")
            
            for asn in sorted(non_peers):
                name = asn_names.get(asn, f'AS{asn}')
                whois_link = f"https://bgp.tools/as/{asn}#whois"
                f.write(f"AS{asn} - {name}\n")
                f.write(f"  BGP.Tools: {whois_link}\n\n")
        
        self.log(f"Results written to:", 1)
        self.log(f"  Potential peers: {peers_filename}", 1)
        self.log(f"  Other ASNs: {non_peers_filename}", 1)
        
        return peers_filename, non_peers_filename
    
    def run_analysis(self):
        """Run the complete analysis"""
        self.log_separator("BGP.TOOLS PEERING ANALYSIS", 1)
        self.log(f"Analysis started at: {datetime.now()}", 1)
        self.log(f"Target ASN: AS{self.target_asn}", 1)
        self.log(f"User Agent: {self.user_agent}", 1)
        self.log(f"Debug level: {self.debug_level}", 1)
        
        try:
            # Step 1: Get ASN information
            self.log("STEP 1: Getting ASN information", 1)
            asn_info = self.get_asn_info()
            
            # Step 2: Download ASN names
            self.log("STEP 2: Downloading ASN names", 1)
            asn_names = self.download_asn_names()
            
            # Step 3: Find related ASNs
            self.log("STEP 3: Finding related ASNs", 1)
            related_asns = self.get_related_asns()
            
            if not related_asns:
                self.log("No related ASNs found", 1)
                return
            
            # Step 4: Analyze relationships
            self.log("STEP 4: Analyzing ASN relationships", 1)
            potential_peers, other_asns = self.analyze_asn_relationships(list(related_asns))
            
            # Step 5: Write results
            self.log("STEP 5: Writing results", 1)
            peers_file, non_peers_file = self.write_results(potential_peers, other_asns, asn_names)
            
            # Final summary
            self.log_separator("FINAL SUMMARY", 1)
            self.log(f"Target ASN: AS{self.target_asn} - {asn_info.get('name', 'Unknown')}", 1)
            self.log(f"Related ASNs found: {len(related_asns)}", 1)
            self.log(f"Potential peers: {len(potential_peers)}", 1)
            self.log(f"Other ASNs: {len(other_asns)}", 1)
            
            self.log("Analysis completed successfully!", 1)
            self.log("NOTE: This analysis is based on heuristics and BGP table data.", 1)
            self.log("For accurate peering information, use PeeringDB or direct BGP data.", 1)
            
        except Exception as e:
            self.log(f"ERROR during analysis: {e}", 1)
            import traceback
            self.log(f"Traceback: {traceback.format_exc()}", 2)
            sys.exit(1)

def get_user_input():
    """Get user input interactively"""
    print("BGP.Tools Peering Analysis Tool")
    print("=" * 50)
    
    # Get ASN
    while True:
        try:
            asn_input = input("Enter ASN to analyze (e.g., 6939): ").strip()
            if not asn_input:
                print("ASN cannot be empty. Please try again.")
                continue
            
            # Remove 'AS' prefix if present
            if asn_input.upper().startswith('AS'):
                asn_input = asn_input[2:]
            
            asn = int(asn_input)
            
            if asn <= 0 or asn > 4294967295:
                print("ASN must be between 1 and 4294967295. Please try again.")
                continue
            
            break
            
        except ValueError:
            print("Invalid ASN format. Please enter a numeric ASN.")
            continue
    
    # Get User Agent
    while True:
        user_agent = input("Enter User-Agent (format: 'description - email'): ").strip()
        if not user_agent:
            print("User-Agent cannot be empty. Please try again.")
            continue
        
        if '@' not in user_agent:
            print("User-Agent should include an email address for contact. Please try again.")
            continue
        
        break
    
    return asn, user_agent

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Analyze potential peering using bgp.tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -a 6939 -u "My Tool - contact@example.com"
  %(prog)s --asn 6939 --useragent "BGP Analysis - admin@mycompany.com"
  %(prog)s  (interactive mode)
        """
    )
    
    parser.add_argument('-a', '--asn', type=int, 
                       help='Target ASN to analyze (e.g., 6939)')
    parser.add_argument('-u', '--useragent', type=str,
                       help='User-Agent string for API requests (format: "description - email")')
    parser.add_argument('--debug', '-d', type=int, default=2, choices=[0, 1, 2, 3],
                       help='Debug level (0=minimal, 1=normal, 2=verbose, 3=debug)')
    
    args = parser.parse_args()
    
    # If no arguments provided, use interactive mode
    if args.asn is None or args.useragent is None:
        print("No arguments provided, entering interactive mode...")
        print()
        target_asn, user_agent = get_user_input()
    else:
        target_asn = args.asn
        user_agent = args.useragent
    
    # Validate ASN
    if target_asn <= 0 or target_asn > 4294967295:
        print(f"Error: Invalid ASN {target_asn}")
        print("ASN must be between 1 and 4294967295")
        sys.exit(1)
    
    # Validate User Agent
    if not user_agent or '@' not in user_agent:
        print("Error: User-Agent must include an email address for contact")
        print("Example: 'My BGP Tool - contact@example.com'")
        sys.exit(1)
    
    # Check connectivity
    print(f"\nChecking bgp.tools connectivity...")
    try:
        headers = {'User-Agent': user_agent}
        response = requests.get("https://bgp.tools/asns.csv", headers=headers, timeout=10)
        print(f"✓ bgp.tools connectivity: OK (HTTP {response.status_code})")
    except requests.RequestException as e:
        print(f"✗ bgp.tools connectivity: FAILED ({e})")
        print("Please check internet connectivity.")
        sys.exit(1)
    
    print(f"\nStarting analysis for AS{target_asn}...")
    print(f"User-Agent: {user_agent}")
    print("=" * 50)
    
    # Create analyzer and run
    analyzer = BGPToolsPeeringAnalyzer(target_asn, user_agent)
    analyzer.debug_level = args.debug
    analyzer.run_analysis()

if __name__ == "__main__":
    main()
