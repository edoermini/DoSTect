import datetime
import threading
from scapy.sendrecv import sniff
from scapy.layers.inet import ICMP, TCP, UDP


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

        self.udp_counter_lock = threading.Lock()
        self.udp_counter = 0

        self.__last_g = 0
        self.__last_ewma = 0

        self.__threshold_exceeded = False

    def __g(self, syn_count):
        """
        Cumulative sum (CUSUM) implementation. \n
        Equation:
            - g_{n} = max( (g_{n-1} + (alpha*mu_{n-1} / sigma^{2}) * (x_{n} - mu_{n-1} - alpha*mu_{n-1}/2) , 0) \n
            - mu_{n} = beta*mu_{n-1} + (1- beta)*x_{n}

        where x_{n} is the metric (number of SYN packets) at interval n

        :param syn_count: x_{n}, the metric (number of SYN packets)
        :return: g_{n}, the volume
        """

        # calulating cusum value
        new_g = self.__last_g + ((self.alpha * self.__last_ewma) / (self.sigma ** 2)) * (
                    syn_count - self.__last_ewma - self.alpha * self.__last_ewma / 2)

        # updating exponentially weighted moving average
        new_ewma = self.beta * self.__last_ewma + (1 - self.beta) * syn_count
        self.__last_ewma = new_ewma

        if new_g > 0:
            self.__last_g = new_g
        else:
            self.__last_g = 0

        return self.__last_g

    def __counter_reader(self):
        """
        - Computes the volume with cusum algorithm __g and checks if threshold has been exceeded.
        - Resets the syn counter for the next interval
        - If threshold is exceeded resets last computed volume to 0.
        - If threshold is not exceeded but in last interval an attack was detected resets last computed ewma to 0.
        """

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
        
        if pkt.haslayer(UDP):
            with self.udp_counter_lock:
                self.udp_counter += 1
                print("UDP packets: {}".format(self.udp_counter))

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
