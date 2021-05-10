import threading
from scapy.sendrecv import sniff
from scapy.layers.inet import TCP


class TrafficCatcher(threading.Thread):
    """
    A thread used for capturing traffic and saving data of interest into DB
    """

    def __init__(self, source, live_capture=False):
        super(TrafficCatcher, self).__init__()

        self.live_capture = live_capture
        self.source = source

        self.syn_counter = 0

    def callback(self, pkt):
        """
        Called by sniff every time it reads a packet.
        If given packet is a TCP packet and has SYN flag set to 1
        increases syn packets counter

        :param pkt: packet read
        """

        syn = 0x02

        if pkt.haslayer(TCP) and pkt[TCP].flags & syn:
            self.syn_counter += 1

            print(f"{pkt[0][1].src} ==> {pkt[0][1].dst} at time {pkt.time}")

    def run(self):

        if self.live_capture:
            sniff(iface=self.source,  prn=self.callback)
        else:
            sniff(offline=self.source, prn=self.callback)


class TrafficAnalyzer(threading.Thread):
    """
    A thread used for analyzing traffic saved into DB from TrafficCatcher
    """