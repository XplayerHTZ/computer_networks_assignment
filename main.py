import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR
from collections import Counter

def analyze_pcap(pcap_file):
    """
    Analyzes a PCAP file, extracts DNS query domains, and counts their occurrences.

    Args:
        pcap_file (str): The path to the PCAP file.

    Returns:
        Counter: A Counter object containing the domain counts, sorted by frequency.
    """
    domain_counts = Counter()
    packets = scapy.rdpcap(pcap_file)

    for packet in packets:
        if DNS in packet and packet[DNS].qr == 0 and packet[DNS].qd:
            domain = packet[DNS].qd.qname.decode('utf-8')
            domain_counts[domain] += 1

    return domain_counts

if __name__ == "__main__":
    pcap_file = "dns_capture_random_20250413_124518.pcapng"
    domain_counts = analyze_pcap(pcap_file)

    print("DNS Query Counts (Most Frequent):\n")
    for domain, count in domain_counts.most_common():
        print(f"{domain}: {count}")
