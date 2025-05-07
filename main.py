import argparse
import os
from glob import glob
from collections import Counter
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR


def analyze_pcap(pcap_file):
    """
    分析PCAP文件，提取DNS查询域并统计出现次数

    参数：
    pcap_file (str): PCAP文件路径

    返回：
    Counter: 按频率排序的域名计数
    """
    domain_count = Counter()
    packets = rdpcap(pcap_file)

    for packet in packets:
        if DNS in packet and packet[DNS].qr == 0 and packet[DNS].qd:
            domain = packet[DNS].qd.qname.decode('utf-8')
            domain_count[domain] += 1

    return domain_count


def get_pcap_files():
    """获取pcap_file目录下所有pcap文件"""
    return glob('pcap_files/*.pcap') + glob('pcap_files/*.pcapng')


def select_pcap_file(files):
    """当有多个文件时让用户选择"""
    print("发现多个PCAP文件:")
    for i, file in enumerate(files, 1):
        print(f"{i}. {os.path.basename(file)}")
    
    while True:
        try:
            choice = int(input("请选择要分析的文件(输入数字): "))
            if 1 <= choice <= len(files):
                return files[choice - 1]
            print("输入无效，请重新输入")
        except ValueError:
            print("请输入数字")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='PCAP文件分析工具')
    parser.add_argument('-n', type=int, help='显示前N个结果')
    args = parser.parse_args()

    files = get_pcap_files()
    if not files:
        print("未找到PCAP文件")
        return

    pcap_file = files[0] if len(files) == 1 else select_pcap_file(files)
    domain_count = analyze_pcap(pcap_file)

    print("\nDNS查询统计(按频率排序):")
    for domain, count in domain_count.most_common(args.n):
        print(f"{domain}: {count}次")


if __name__ == "__main__":
    main()
