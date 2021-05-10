import threading
from scapy import *
from scapy.utils import rdpcap
from scapy.sendrecv import sniff
from scapy.layers.inet import TCP, UDP

# TCP-Flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


        #pkt.show() # debug statement


class TrafficCatcher(threading.Thread):


    """
    A thread used for capturing traffic and saving data of interest into DB
    """

    def __init__(self, stype, source):
        super(TrafficCatcher, self).__init__()
        self.stype = stype
        self.source = source


    def callback(self, pkt):
        if pkt.haslayer(TCP) and pkt[TCP].flags & SYN:
            try:
                print(f"{pkt[0][1].src} ==> {pkt[0][1].dst} at time {pkt.time}")
            
            except:
                pass
            

    def run(self):
        if self.stype == 0: #Live capture
            print(self.source)
            print( "live  capture")
            pkts = sniff(iface=self.source,  prn = self.callback, lfilter = lambda x: x.haslayer(TCP) and x[TCP].flags & SYN)   
            counter = 0
            for packet in pkts:
                counter+=1
               
            print("Total SYN packets live: ", counter)
        
        else: #PCAP FIle sniffing
            # Filter for  TCP/UDP layer and check SYN = 1 in packet flags
            #pkts = sniff(offline=self.source, lfilter = lambda x: x.haslayer(TCP) and x[TCP].flags & SYN)  
            pkts = sniff(offline=self.source, prn = self.callback, lfilter = lambda x: x.haslayer(TCP) and x[TCP].flags & SYN)  
            #pkts = rdpcap(self.source)

            count = 0
            for packet in pkts:
                count+=1
                #print(f"{packet[0][1].src} ==> {packet[0][1].dst} at time {packet[0][1].time}")
            
            print("Total SYN packets: ", count)

class TrafficAnalyzer(threading.Thread):
    """
    A thread used for analyzing traffic saved into DB from TrafficCatcher
    """
    pass