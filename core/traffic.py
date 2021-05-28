import threading
from scapy.sendrecv import sniff
from scapy.layers.inet import TCP, UDP
from .detectors import UDPNPCusumDetector, SYNNPCusumDetector
import time

class TrafficAnalyzer:
    """
    A thread used for capturing traffic and saving data of interest into DB
    """

    def __init__(self, source, live_capture=False, time_interval=5):
        self.time_stamp = time.time()
        self.source = source
        self.live_capture = live_capture
        self.time_interval = time_interval

        self.syn_cusum = SYNNPCusumDetector()
        self.udp_cusum = UDPNPCusumDetector()

        self.syn_counter = 0
        self.synack_counter = 0

        self.udp_counter = 0

    def __counter_reader(self):
        """
        - Computes the volume with cusum algorithm __g and checks if threshold has been exceeded.
        - Resets the syn counter for the next interval
        - If threshold is exceeded resets last computed volume to 0.
        - If threshold is not exceeded but in last interval an attack was detected resets last computed ewma to 0.
        """

        self.syn_cusum.analyze(self.syn_counter, self.synack_counter)
        #self.udp_cusum.analyze(self.udp_counter)

        self.syn_counter = 0
        self.synack_counter = 0
        self.udp_counter = 0

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
        diff_time = time.time() - self.time_stamp

        # controllo se sono passati almeno 5 secondi (intervallo  di tempo che abbiamo scelto noi) e non più di 10
        # in tal caso chiamo counter_reader ed incremento il time_stamp (che ricorda quando ho effettuato l'ultimo controllo)
        if diff_time >= self.time_interval and diff_time < self.time_interval * 2:
            self.__counter_reader()
            self.time_stamp += self.time_interval
        # se ne sono passati più di 10 invece: prendo la parte intera del rapporto tra il tempo passato e la durata dell'intervallo (5 sec)
        # che indica quanti intervalli di tempo ho "perso" dall'ultima invocazione della callback
        # a questo punto eseguo una counter_reader per ogni intervallo "perso", incrementando il timestamp di 5 ad ogni iterazione
        elif diff_time > self.time_interval * 2:
            i = int(diff_time / self.time_interval)
            print(diff_time)
            print(i)
            for c in range(i):
                self.__counter_reader()
                self.time_stamp += self.time_interval

        if pkt.haslayer(TCP):
            if (pkt[TCP].flags & syn) and not (pkt[TCP].flags & ack):
                self.syn_counter += 1
            elif (pkt[TCP].flags & syn) and (pkt[TCP].flags & ack):
                self.synack_counter += 1

        if pkt.haslayer(UDP):
            self.udp_counter += 1

    def start(self):
        """
        Starts packet capturing and analyzing
        """

        if self.live_capture:
            sniff(iface=self.source, prn=self.__callback)
        else:
            sniff(offline=self.source, prn=self.__callback)
