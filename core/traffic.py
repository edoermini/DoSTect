import threading
from scapy.sendrecv import sniff
from scapy.layers.inet import TCP, IP
from .detectors import SYNNPCusumDetector, SYNCusumDetector
import time
import netifaces as ni


class TrafficCatcher:

    def __init__(self, source: str, plot=None, parametric=False, time_interval=5, threshold=0.65):

        self._time_interval = time_interval
        self._source = source
        self._threshold = threshold
        self._graph = False

        if plot is not None:
            self.plot = plot
            self._graph = True

        if parametric:
            self._syn_cusum = SYNCusumDetector(threshold=threshold)
        else:
            self._syn_cusum = SYNNPCusumDetector()

        self._syn_counter = 0
        self._synack_counter = 0

    def _counter_reader(self):
        """
        - Computes the volume with cusum algorithm __g and checks if threshold has been exceeded.
        - Resets the syn counter for the next interval
        - If threshold is exceeded resets last computed volume to 0.
        - If threshold is not exceeded but in last interval an attack was detected resets last computed ewma to 0.
        """

        volume, threshold = self._syn_cusum.analyze(self._syn_counter, self._synack_counter)

        if self._graph:
            ts1 = int(time.time())
            self.plot.update_data([volume, threshold], ts1)

        self._syn_counter = 0
        self._synack_counter = 0


class LiveCatcher(TrafficCatcher):
    """
    A thread used for capturing traffic and saving data of interest into DB
    """

    def __init__(self, source, plot=None, parametric=False, time_interval=5, threshold=0.65):
        super().__init__(source, plot, parametric, time_interval, threshold)

        self.__timestamp = time.time()
        self.__ipv4_address = ni.ifaddresses(self._source)[ni.AF_INET][0]['addr']

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
        if self._time_interval <= diff_time < self._time_interval * 2:

            print(pkt.time)
            self._counter_reader()
            self.__timestamp += self._time_interval

        # if it's been more than self.__time_interval*2 seconds:
        elif diff_time > self._time_interval * 2:

            # number of lost intervals
            lost_intervals_number = int(diff_time / self._time_interval)

            # for each lost interval will be called self.__counter_reader()
            for c in range(lost_intervals_number):
                self._counter_reader()
                self.__timestamp += self._time_interval

        if pkt.haslayer(TCP):
            if (pkt[TCP].flags & syn) and not (pkt[TCP].flags & ack) and (pkt[IP].dst == self.__ipv4_address):
                self._syn_counter += 1
            elif (pkt[TCP].flags & syn) and (pkt[TCP].flags & ack) and (pkt[IP].src == self.__ipv4_address):
                self._synack_counter += 1

    def start(self):
        """
        Starts packet capturing and analyzing
        """

        sniff(iface=self._source, prn=self.__callback, store=0)

class OfflineCatcher(TrafficCatcher):
    """
    A thread used for capturing traffic and saving data of interest into DB
    """

    def __init__(self, source, ipv4_address, plot=None, parametric=False, time_interval=5, threshold=0.65):

        super().__init__(source, plot, parametric, time_interval, threshold)

        self.__ipv4_address = ipv4_address

        # timestamp of first packet in a new time interval
        self.__first_pkt_timestamp = 0

    def __callback(self, pkt):
        """
        Called by sniff every time it reads a packet.
        If given packet is a TCP packet and has SYN flag set to 1
        increases syn packets counter

        :param pkt: packet read
        """

        syn = 0x2
        ack = 0x10

        if self.__first_pkt_timestamp == 0:
            self.__first_pkt_timestamp = pkt.time

        # current time minus last computation time
        #diff_time = time.time() - self.__timestamp
        diff_time = pkt.time - self.__first_pkt_timestamp

        # checks if it's been at least self.__time_interval seconds and not more than self.__time_interval*2
        if self._time_interval <= diff_time:
            print(pkt.time)
            self._counter_reader()
            self.__first_pkt_timestamp = 0

        if pkt.haslayer(TCP):
            if (pkt[TCP].flags & syn) and not (pkt[TCP].flags & ack) and (pkt[IP].dst == self.__ipv4_address):
                self._syn_counter += 1
            elif (pkt[TCP].flags & syn) and (pkt[TCP].flags & ack) and (pkt[IP].src == self.__ipv4_address):
                self._synack_counter += 1

    def start(self):
        """
        Starts packet capturing and analyzing
        """

        sniff(offline=self._source, prn=self.__callback, store=0)
