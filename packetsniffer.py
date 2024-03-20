import socket
import struct
from datetime import datetime

def eth_header(raw_data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', raw_data[:14])
    return socket.htons(proto), dest_mac, src_mac

def ipv4_header(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    return version, header_length, ttl, proto, src, target, raw_data[header_length:]

def tcp_segment(raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgment, offset, raw_data[offset:]

def udp_segment(raw_data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', raw_data[:8])
    return src_port, dest_port, size, raw_data[8:]

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print("Packet sniffer started. Press Ctrl+C to stop.")

    with open('captured_packets.txt', 'a') as f:
        try:
            while True:
                raw_data, addr = conn.recvfrom(65536)
                eth_proto, _, _ = eth_header(raw_data)
                if eth_proto == 8:  # IPv4
                    version, header_length, ttl, proto, src, target, data = ipv4_header(raw_data[14:])
                    
                    if proto == 6:  # TCP
                        src_port, dest_port, sequence, acknowledgment, offset, tcp_data = tcp_segment(data)
                        f.write(f"{datetime.now()} TCP Packet: Src: {src}:{src_port}, Dst: {target}:{dest_port}, Seq: {sequence}, Ack: {acknowledgment}, Data Length: {len(tcp_data)}\n")
                    
                    elif proto == 17:  # UDP
                        src_port, dest_port, size, udp_data = udp_segment(data)
                        f.write(f"{datetime.now()} UDP Packet: Src: {src}:{src_port}, Dst: {target}:{dest_port}, Size: {size}\n")

        except KeyboardInterrupt:
            print("\nPacket sniffer stopped.")
            conn.close()

if __name__ == "__main__":
    main()
