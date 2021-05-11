import datetime
import threading
from scapy.sendrecv import sniff
from scapy.layers.inet import TCP


class TrafficAnalyzer:
    """
    A thread used for capturing traffic and saving data of interest into DB
    """

    def __init__(self, source, time_interval=5, alpha=0.5, beta=0.99, live_capture=False):
        self.live_capture = live_capture
        self.source = source

        self.syn_counter_lock = threading.Lock()
        self.syn_counter = 0

        self.alpha = alpha
        self.beta = beta
        self.threshold = 5
        self.sigma = 100

        self.time_interval = time_interval

        self.last_g = 0
        self.last_ewma = 0

    def __ewma(self, syn_count) -> float:
        new_ewma = self.beta*self.last_ewma + (1-self.beta)*syn_count
        self.last_ewma = new_ewma

        return new_ewma

    def __g(self, syn_count):
        new_g = self.last_g + ((self.alpha*self.last_ewma)/(self.sigma**2))*(syn_count - self.last_ewma - self.alpha*self.last_ewma/2)

        self.__ewma(syn_count)

        if new_g > 0:
            self.last_g = new_g
        else:
            self.last_g = 0

        return self.last_g

    def __counter_reader(self):
        syn_count = 0

        with self.syn_counter_lock:
            syn_count = self.syn_counter
            self.syn_counter = 0

        val = self.__g(syn_count)
        print(val)

        
        if val > self.threshold:
            self.last_g = 0
        threading.Timer(self.time_interval, self.__counter_reader).start()

    def __callback(self, pkt):
        """
        Called by sniff every time it reads a packet.
        If given packet is a TCP packet and has SYN flag set to 1
        increases syn packets counter

        :param pkt: packet read
        """

        syn = 0x02

        if pkt.haslayer(TCP) and pkt[TCP].flags & syn:

            with self.syn_counter_lock:
                self.syn_counter += 1

    def start(self):
        """

        :param time_interval:
        :return:
        """

        # start thread that runs every time_interval seconds
        self.__counter_reader()

        if self.live_capture:
            sniff(iface=self.source,  prn=self.__callback)
        else:
            sniff(offline=self.source, prn=self.__callback)

