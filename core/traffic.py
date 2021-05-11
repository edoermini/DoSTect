import datetime
import threading
from scapy.sendrecv import sniff
from scapy.layers.inet import TCP


class TrafficAnalyzer:
    """
    A thread used for capturing traffic and saving data of interest into DB
    """

    def __init__(self, source, live_capture=False, threshold=10, sigma=100, time_interval=5, alpha=0.5, beta=0.99):
        self.source = source
        self.live_capture = live_capture

        self.threshold = threshold
        self.sigma = sigma
        self.time_interval = time_interval
        self.alpha = alpha
        self.beta = beta

        self.syn_counter_lock = threading.Lock()
        self.syn_counter = 0

        self.__last_g = 0
        self.__last_ewma = 0

        self.__threshold_exceeded = False

    def __ewma(self, syn_count) -> float:
        new_ewma = self.beta * self.__last_ewma + (1 - self.beta) * syn_count
        self.__last_ewma = new_ewma

        return new_ewma

    def __g(self, syn_count):
        new_g = self.__last_g + ((self.alpha * self.__last_ewma) / (self.sigma ** 2)) * (
                    syn_count - self.__last_ewma - self.alpha * self.__last_ewma / 2)

        self.__ewma(syn_count)

        if new_g > 0:
            self.__last_g = new_g
        else:
            self.__last_g = 0

        return self.__last_g

    def __counter_reader(self):
        syn_count = 0

        with self.syn_counter_lock:
            syn_count = self.syn_counter
            self.syn_counter = 0

        val = self.__g(syn_count)
        print(val)

        if val > self.threshold:
            print("[!] Warning DDoS detected")
            self.__last_g = 0
            self.__threshold_exceeded = True
        else:
            # not DDoS detected

            if self.__threshold_exceeded:
                # DDoS stopped
                # last check recorded an attack

                self.__last_ewma = 0
                self.__threshold_exceeded = False

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
        Starts packet capturing and analyzing
        """

        # start thread that runs every time_interval seconds
        self.__counter_reader()

        if self.live_capture:
            sniff(iface=self.source, prn=self.__callback)
        else:
            sniff(offline=self.source, prn=self.__callback)
