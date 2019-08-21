import socket, sys
from struct import *
 
if __name__ == "__main__":
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
 
    if (len(sys.argv) <= 1):
        print("Script usage: python2 sniffer.py <IP address to filter>")
        sys.exit(0)
 
    while True:
        packet = s.recvfrom(65565)[0]
        eth_header = packet[:14]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])
 
        if eth_protocol == 8: # IP
            ip_header = packet[14:34]
            iph = unpack('!BBHHHBBH4s4s', ip_header)
            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])
            #print "Source IP: " + s_addr
            #print "Destination IP: " + d_addr
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
 
            if (s_addr == sys.argv[1]) or (d_addr == sys.argv[1]):
                #print "Source IP: " + s_addr + " | Destination IP: " + d_addr
                if protocol == 6: # TCP
                    t = iph_length + 14
                    tcp_header = packet[t:t+20]
                    tcph = unpack('!HHLLBBHHH', tcp_header)
                    source_port = tcph[0]
                    dest_port = tcph[1]
                    #if (str(dest_port) == "88") or (str(dest_port) == "6088"):
                    #    print "Source IP: " + s_addr + " | Destination IP: " + d_addr
                    print "TCP: SP=" + str(source_port) + " DP=" + str(dest_port)
 
                elif protocol == 1: # ICMP
                    icmp_header = packet[20:24]
                    icmph = unpack('!BBH', icmp_header)
                    icmp_type = icmph[0]
                    code = icmph[1]
                    checksum = icmph[2]
                    print "ICMP: Type="  + str(icmp_type) + " Code=" + str(code)
 
                elif protocol == 17: # UDP
                    u = iph_length + 14
                    udp_header = packet[u:u+8]
                    udph = unpack('!HHHH', udp_header)
                    source_port = udph[0]
                    dest_port = udph[1]
                    print "UDP: SP=" + str(source_port) + " DP=" + str(dest_port)
 
                else:
                    print('Unknown Protocol!')
 
