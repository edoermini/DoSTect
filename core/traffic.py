import threading
from scapy.sendrecv import sniff
from scapy.layers.inet import TCP, UDP


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
        self.source = source
        self.live_capture = live_capture
        self.time_interval = time_interval

        self.syn_counter = Counter(threshold=10, sigma=100, alpha=0.5, beta=0.95)
        self.udp_counter = Counter(threshold=10, sigma=1000, alpha=0.5, beta=0.95)

    def __counter_reader(self):
        """
        - Computes the volume with cusum algorithm __g and checks if threshold has been exceeded.
        - Resets the syn counter for the next interval
        - If threshold is exceeded resets last computed volume to 0.
        - If threshold is not exceeded but in last interval an attack was detected resets last computed ewma to 0.
        """

        syn_count = self.syn_counter.get_value()
        udp_count = self.udp_counter.get_value()

        self.syn_counter.compute_volume()
        self.udp_counter.compute_volume()

        print("SYN packets (count, volume): " +
              str(syn_count) + ", " +
              str(self.syn_counter.get_volume())
              )

        print("UDP packets (count, volume): " +
              str(udp_count) + ", " +
              str(self.udp_counter.get_volume())
              )

        print()

        if self.syn_counter.threshold_exceeded():
            print("SYN flooding DoS detected!")

        if self.udp_counter.threshold_exceeded():
            print("UDP flooding DoS detected!")

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
            self.syn_counter.increase()
        elif pkt.haslayer(UDP):
            self.udp_counter.increase()

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
