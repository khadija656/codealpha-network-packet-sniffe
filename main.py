from scapy.all import *
from datetime import datetime

packet_count = 0

log_file = open("log.txt", "w", encoding="utf-8")

def packet_info(packet):
    global packet_count
    packet_count += 1

    output = "\n" + "="*60 + "\n"
    output += f"Packet No: {packet_count}\n"
    output += f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"

    if packet.haslayer(IP):
        ip = packet[IP]
        output += f"Source IP: {ip.src}\n"
        output += f"Destination IP: {ip.dst}\n"

        proto = ip.proto
        if proto == 6:
            output += "Protocol: TCP\n"
        elif proto == 17:
            output += "Protocol: UDP\n"
        elif proto == 1:
            output += "Protocol: ICMP\n"
        else:
            output += f"Protocol: {proto}\n"

    if packet.haslayer(TCP):
        output += f"Source Port: {packet[TCP].sport}\n"
        output += f"Destination Port: {packet[TCP].dport}\n"

    elif packet.haslayer(UDP):
        output += f"Source Port: {packet[UDP].sport}\n"
        output += f"Destination Port: {packet[UDP].dport}\n"

    if packet.haslayer(Raw):
        payload = str(packet[Raw].load[:50])
        output += f"Payload: {payload}\n"

    print(output)

    # SAVE TO FILE
    log_file.write(output)
    log_file.flush()

print("🚀 Professional Network Sniffer Running...")
print("Saving output to log.txt...\n")

sniff(prn=packet_info, count=10, store=0)