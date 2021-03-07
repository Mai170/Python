import pyfiglet
import sys
import socket
from datetime import datetime
import subprocess
import os
from scapy.all import *

ascii_banner = pyfiglet.figlet_format("MEMO'S NETWORK")
print(ascii_banner)
print("MAI ALAA ITI41")
target_ip = input("Enter Target ip:")
start = int(input("Enter start range:"))
end = int(input("Enter end range:"))


def tcp(target_ip, start, end):
    try:
        ports = []
        strports = ""

        # will scan ports between 1 to 65,535 
        for port in range(start, end):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)

            # returns an error indicator 
            result = s.connect_ex((target_ip, port))
            if result == 0:
                print("Port {} is open".format(port))
                ports.append(str(port))
            s.close()
            strports = ','.join(ports)
        os.system("nmap -T4 -v -sC -sV -oN output.txt -p{} --append-output ".format(strports) + str(target_ip))

    except KeyboardInterrupt:
        print("\n Exitting Program !!!!")
        sys.exit()

    except socket.error:
        print("\ Server not responding !!!!")
        sys.exit()


def udp(target_ip, start, end):
    try:
        ports = []
        strports = ""
        for port in range(start, end):
            MESSAGE = "ping"
            portOpen = False
            for _ in range(5):  # udp is unreliable.Packet loss may occur
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                    sock.settimeout(3)
                    sock.sendto(MESSAGE.encode('utf_8'), (str(ip), port))
                    data, addr = sock.recvfrom(1024)
                    print("data = {}".format(data))
                    sock.close()
                    portOpen = True
                    break
                except socket.timeout:
                    pass
            if portOpen:
                print('port open!')
            else:
                print('port closed!')

    except socket.error:
        print("Couldn't connect to server.")
        sys.exit()

ptype = int(input("Enter 1 to scan TCP or 2 for UDP:"))

if ptype == 1:
    tcp(target_ip, start, end)

elif ptype == 2:
    udp(target_ip, start, end)
def print_summary(pkt):
    if IP in pkt:
        ip_src=pkt[IP].src
        ip_dst=pkt[IP].dst
    if TCP in pkt:
        tcp_sport=pkt[TCP].sport
        tcp_dport=pkt[TCP].dport

        print (" IP src " + str(ip_src) + " TCP sport " + str(tcp_sport) )
     
       

    
    if  ( pkt[IP].src == "192.168.10.0/24"):
        print("IN network")
        
             

# or it possible to filter with filter parameter...!

sis=int(input("Type 3 for sniffing traffic: "))
if sis==3:
    sniff(filter="ip and host 192.168.10.77",prn=print_summary)
      

   
  
