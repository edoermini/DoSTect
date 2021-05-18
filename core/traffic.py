import threading
from scapy.sendrecv import sniff
from scapy.layers.inet import TCP, UDP
from .forecasting import UDPNPCusum, SYNNPCusum
import time


class Counter:
    def __init__(self, threshold, sigma, alpha, beta):
        self.threshold = threshold
        self.sigma = sigma
        self.alpha = alpha
        self.beta = beta

        self.counter_lock = threading.Lock()
        self.counter = 0

        self.__last_cusum = 0
        self.__last_ewma = 0

        self.__threshold_exceeded = False

    def compute_volume(self):
        """
        Cumulative sum (CUSUM) implementation. \n
        Equation:
            - g_{n} = max( (g_{n-1} + (alpha*mu_{n-1} / sigma^{2}) * (x_{n} - mu_{n-1} - alpha*mu_{n-1}/2) , 0) \n
            - mu_{n} = beta*mu_{n-1} + (1- beta)*x_{n}

        where x_{n} is the metric (number of SYN packets) at interval n
        """

        counter = 0

        with self.counter_lock:
            counter = self.counter
            self.counter = 0

        # calulating cusum value
        new_cusum = self.__last_cusum + ((self.alpha * self.__last_ewma) / (self.sigma ** 2)) * (
                counter - self.__last_ewma - self.alpha * self.__last_ewma / 2)

        self.__last_cusum = max(new_cusum, 0)

        # updating exponentially weighted moving average
        new_ewma = self.beta * self.__last_ewma + (1 - self.beta) * counter
        self.__last_ewma = new_ewma

        # checking violation
        if self.__last_cusum > self.threshold:
            self.__last_cusum = 0
            self.__threshold_exceeded = True
        else:
            # violation not detected
            self.__threshold_exceeded = False

    def get_volume(self):
        return self.__last_cusum

    def increase(self):
        with self.counter_lock:
            self.counter += 1

    def get_value(self):
        return self.counter

    def threshold_exceeded(self):
        return self.__threshold_exceeded


class TrafficAnalyzer:
    """
    A thread used for capturing traffic and saving data of interest into DB
    """

    def __init__(self, source, live_capture=False, time_interval=5):
        self.time_stamp = time.time()
        self.source = source
        self.live_capture = live_capture
        self.time_interval = time_interval

        self.syn_cusum = SYNNPCusum()
        self.udp_cusum = UDPNPCusum()

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
        self.udp_cusum.analyze(self.udp_counter)

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
