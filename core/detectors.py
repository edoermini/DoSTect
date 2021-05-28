import math
from .forecasting import ExponentialSmoothing, SingleExponentialSmoothing, DoubleExponentialSmoothing


class CusumDetector:
    """
    Parametric cumulative sum implementation for anomaly detection
    """

    def __init__(self, threshold, sigma, alpha=0.5, ewma_factor=0.98):
        self._threshold = threshold

        # the gaussian's variance
        # intuitively indicates how much the new value is important in volume (self._test_statistics) computing
        self._sigma_square = sigma ** 2

        # percentage beyond which the mean value (self.__mu) can be considered as anomalous behaviour
        self._alpha = alpha

        # exponentially weighted moving average factor
        self.__ewma_factor = ewma_factor

        # exponentially weighted moving average of values in window
        self._mu = 0

        # the volume computed (used to check threshold excess)
        self._test_statistic = 0

        self._under_attack = False

    def _data_smoothing(self, value: float):
        """
        Cumulative sum (CUSUM) implementation. \n
        Equation:
            - g_{n} = max( (g_{n-1} + (alpha*mu_{n-1} / sigma^{2}) * (x_{n} - mu_{n-1} - alpha*mu_{n-1}/2) , 0) \n
            - mu_{n} = beta*mu_{n-1} + (1- beta)*x_{n}
        where x_{n} is the metric (number of SYN packets) at interval n
        """

        # calulating cusum value
        new_cusum = self._test_statistic + ((self._alpha * self._mu) / (self._sigma_square)) * (
                value - self._mu - self._alpha * self._mu / 2)

        self._test_statistic = max(new_cusum, 0)

        # updating exponentially weighted moving average
        self._mu = self.__ewma_factor * self._mu + (1 - self.__ewma_factor) * value

    def _cusum_detection(self):
        # checking violation
        if self._test_statistic > self._threshold:
            self._test_statistic = 0
            self._under_attack = True
        else:
            # violation not detected
            self._under_attack = False

    def update(self, value: float):
        self._data_smoothing(value)
        self._cusum_detection()

        return self._test_statistic


class NPCusumDetector:
    """
    Non parametric cumulative sum implementation for anomaly detection
    """

    def __init__(self,
                 start_alarm_delay,
                 stop_alarm_delay,
                 smoothing: ExponentialSmoothing,
                 window_size: int = 3,
                 ewma_factor: float = 0.98,
                 outlier_threshold: float = 0.65
                 ):

        # the volume computed (used to check threshold excess)
        self._test_statistic = 0

        self._under_attack = False

        # the attack detection threshold used by cusum algorithm
        self._detection_threshold = 0

        # a threshold for outlier identification
        self.__outlier_threshold = outlier_threshold

        # accumulates the threshold violations
        self.__outlier_cum = 0

        # accumulates the alarming time
        self.__alarm_dur = 0

        # time delay required for identifying the starting of an attack
        self.__start_alarm_delay = start_alarm_delay

        # maximum number of elements inside window
        self.__window_size = window_size
        # list of last self.__window_size elements
        self.__window = []

        # smoothing objects that implements the smoothing function
        self.smoothing = smoothing

        # exponentially weighted moving average factor
        self.__ewma_factor = ewma_factor

        # exponentially weighted moving average of values in window
        self._mu = 0

        # variance of values in window
        self._sigma = 0

        # once read self.__window_size values starts to apply cusum to new values
        self.__start_cusum = False

        # value used to calculate the test statistic
        self._z = 0

        # time delay required for identifying the ending of an attack
        self.__stop_alarm_delay = stop_alarm_delay

        # counts times that self.__z is negative after a certain time of attack detection
        self.__attack_ending_cum = 0

    def _outlier_processing(self, value: float):

        if value > self.__outlier_threshold:
            # outlier threshold exceeded
            # the value is an outlier

            if not self._under_attack:
                # not already under attack

                self.__outlier_cum += 1

                if self.__outlier_cum == self.__start_alarm_delay:
                    # reached required times to detect an attack

                    print("DoS attack detected")
                    self.__outlier_cum = self.__start_alarm_delay - 1
                    self._under_attack = True
                    self.__alarm_dur += 1
            else:
                # already under attack

                self.__alarm_dur += 1

        else:
            # value is not an outlier

            if self.__outlier_cum > 0:
                self.__outlier_cum -= 1

    def _data_smoothing(self, value: float):

        if len(self.__window) < self.__window_size:
            # filling window

            self.__window.append(value)
            return

        elif len(self.__window) == self.__window_size and not self.__start_cusum:
            # first time that the window is full

            self.__window.append(value)
            self.__window = self.__window[1:]

            # calculating mean value
            mean = sum(self.__window) / self.__window_size

            # initializing smoothing function first value
            smoothing_init_values = [
                mean,                                                           # initial value for ewma computation
                (self.__window[-1] - self.__window[0]) / self.__window_size-1,  # initial value for trend computation
            ]
            self.smoothing.initialize(smoothing_init_values, self.__window)

            # calculating simga value
            square_sum = 0
            for val in self.__window:
                square_sum += (val - mean) ** 2

            self._sigma = math.sqrt(square_sum / self.__window_size)

            self.__start_cusum = True

            return

        self.__window.append(value)
        self.__window = self.__window[1:]

        # calculating window mean
        window_mean = sum(self.__window) / self.__window_size

        # saving previous values of mu and sigma
        last_mu = self.smoothing.get_smoothed_value()
        last_sigma_square = self._sigma ** 2

        # calculating window exponentially weighted moving average
        self.smoothing.forecast(window_mean)

        # calculating simga value
        self._sigma = math.sqrt(
            self.__ewma_factor * last_sigma_square +
            (1 - self.__ewma_factor) * (window_mean - last_mu) ** 2
        )

        self._z = window_mean - last_mu - 3 * last_sigma_square

    def _cusum_detection(self):

        if not self.__start_cusum:
            return

        self._test_statistic = max(self._test_statistic + self._z, 0)

        if not self._under_attack:

            if self._z > 0:
                # adjusting detection threshold

                if self._detection_threshold == 0:
                    self._detection_threshold = self._z * self.__start_alarm_delay
                else:
                    self._detection_threshold = self._detection_threshold / 2 + \
                                                self._z * self.__start_alarm_delay / 2

                if self._test_statistic >= self._detection_threshold:
                    # under attack

                    print("DoS attack detected")
                    self._under_attack = True
                    self.__alarm_dur += 1
            else:
                # not under attack and not necessity of threshold adjustment
                return
        else:
            # under attack
            # checking end of an attack throughout sign of self.__z

            if self._z <= 0:
                self.__attack_ending_cum += 1

                if self.__attack_ending_cum == self.__stop_alarm_delay:
                    # reached required time delay before detect an attack ending

                    print("DoS ended")
                    self._under_attack = False
                    self._test_statistic = 0
                    self.__attack_ending_cum = 0
                    self._detection_threshold = 0

                    if self.__alarm_dur < 6:
                        self.__alarm_dur = 0
                else:
                    # continuing to raise alarm
                    self.__alarm_dur += 1

    def update(self, value: float):
        self._outlier_processing(value)
        self._data_smoothing(value)
        self._cusum_detection()

        return self._test_statistic


class SYNNPCusumDetector(NPCusumDetector):
    def __init__(self):
        super(SYNNPCusumDetector, self).__init__(4, 4, DoubleExponentialSmoothing())

    def analyze(self, syn_count: int, synack_count: int):
        syn_value = 0.0

        if syn_count != 0:
            syn_value = float(syn_count - synack_count) / float(syn_count)

        self.update(syn_value)

        print("SYN Value: %.10f" % syn_value)
        print("SYN Zeta: " + str(self._z))
        print("SYN Sigma: " + str(self._sigma))
        print("SYN volume: " + str(self._test_statistic))
        print("SYN Mu: " + str(self._mu))
        print("SYN Threshold: " + str(self._detection_threshold))
        print()

        return self._test_statistic


class UDPNPCusumDetector(NPCusumDetector):
    def __init__(self, mean_window_dim=10):
        super(UDPNPCusumDetector, self).__init__(4, 4, SingleExponentialSmoothing(), window_size=3)

        self.__mean_window_dim = mean_window_dim
        self.__mean_window = []

    def analyze(self, value: int):
        udp_value = 0.0
        udp_mean = 0.0

        if not self._under_attack:
            # updating udp mean factor
            self.__mean_window.append(value)

            window_len = len(self.__mean_window)

            if self.__mean_window_dim >= window_len > 0:
                udp_mean = sum(self.__mean_window) / window_len

            elif window_len == self.__mean_window_dim + 1:
                self.__mean_window = self.__mean_window[1:]
                udp_mean = sum(self.__mean_window) / self.__mean_window_dim

        else:
            udp_mean = sum(self.__mean_window) / self.__mean_window_dim

        print(self.__mean_window)

        distance_from_mean = float(value) - udp_mean * 1.2

        print("Value: ", value)
        print("Mean: ", udp_mean)
        print("Distance from mean: ", distance_from_mean)

        if value != 0 and distance_from_mean > 0:
            udp_value = distance_from_mean / float(value)

        self.update(udp_value)

        print("UDP Value: %.10f" % udp_value)
        print("UDP Zeta: " + str(self._z))
        print("UDP Sigma: " + str(self._sigma))
        print("UDP volume: " + str(self._test_statistic))
        print("UDP Mu: " + str(self._mu))
        print("UDP Threshold: " + str(self._detection_threshold))
        print()

        return self._test_statistic
