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


class TrafficCatcher(threading.Thread):


    """
    A thread used for capturing traffic and saving data of interest into DB
    """

 

class TrafficAnalyzer(threading.Thread):
    """
    A thread used for analyzing traffic saved into DB from TrafficCatcher
    """
    pass
