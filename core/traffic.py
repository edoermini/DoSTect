import threading
from scapy.sendrecv import sniff
from scapy.layers.inet import TCP, IP
from .detectors import SYNNPCusumDetector, SYNCusumDetector
import time
import netifaces as ni


class TrafficAnalyzer:
    """
    A thread used for capturing traffic and saving data of interest into DB
    """
    

    def __init__(self, source, plot, live_capture=False, time_interval=5):
        self.__timestamp = time.time()
        self.__source = source
        self.__live_capture = live_capture
        self.__time_interval = time_interval
        self.plot = plot
        
        self.__syn_cusum = SYNCusumDetector()

        self.__syn_counter = 0
        self.__synack_counter = 0

    def __counter_reader(self):
        """
        - Computes the volume with cusum algorithm __g and checks if threshold has been exceeded.
        - Resets the syn counter for the next interval
        - If threshold is exceeded resets last computed volume to 0.
        - If threshold is not exceeded but in last interval an attack was detected resets last computed ewma to 0.
        """

        volume = self.__syn_cusum.analyze(self.__syn_counter, self.__synack_counter)

        ts1 = int(time.time())
        self.plot.update_syn_data([volume,10], ts1)

        self.__syn_counter = 0
        self.__synack_counter = 0

    def __callback(self, pkt):
        """
        Called by sniff every time it reads a packet.
        If given packet is a TCP packet and has SYN flag set to 1
        increases syn packets counter

        :param pkt: packet read
        """

        syn = 0x2
        ack = 0x10

        # current time minus last computation time
        diff_time = time.time() - self.__timestamp

        # checks if it's been at least self.__time_interval seconds and not more than self.__time_interval*2
        if self.__time_interval <= diff_time < self.__time_interval * 2:
            self.__counter_reader()
            self.__timestamp += self.__time_interval

        # if it's been more than self.__time_interval*2 seconds:
        elif diff_time > self.__time_interval * 2:

            # number of lost intervals
            lost_intervals_number = int(diff_time / self.__time_interval)

            # for each lost interval will be called self.__counter_reader()
            for c in range(lost_intervals_number):
                self.__counter_reader()
                self.__timestamp += self.__time_interval

        local_addr = ni.ifaddresses(self.__source)[ni.AF_INET][0]['addr']

        if pkt.haslayer(TCP):
            if (pkt[TCP].flags & syn) and not (pkt[TCP].flags & ack) and (pkt[IP].dst == local_addr):
                self.__syn_counter += 1
            elif (pkt[TCP].flags & syn) and (pkt[TCP].flags & ack) and (pkt[IP].src == local_addr):
                self.__synack_counter += 1

        

    def start(self):
        """
        Starts packet capturing and analyzing
        """

        if self.__live_capture:
            sniff(iface=self.__source, prn=self.__callback, store=0)
        else:
            sniff(offline=self.__source, prn=self.__callback, store=0)
