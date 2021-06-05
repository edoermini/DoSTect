import math
from .forecasting import SingleExponentialSmoothing, DoubleExponentialSmoothing


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class CusumDetector:
    """
    Parametric cumulative sum implementation for anomaly detection
    """

    def __init__(self, threshold, alpha=0.5, window_size=3):

        self._detection_threshold = threshold

        self._sigma = 0

        # percentage beyond which the mean value (self.__mu) can be considered as anomalous behaviour
        self._alpha = alpha

        # the volume computed (used to check threshold excess)
        self._test_statistic = 0

        self._under_attack = False

        # smoothing objects that implements the smoothing function
        self._smoothing = SingleExponentialSmoothing()

        # maximum number of elements inside window
        self.__window_size = window_size
        # list of last self.__window_size elements
        self.__window = []

        # once read self.__window_size values starts to apply cusum to new values
        self.__start_cusum = False

        self._z = 0

    def _data_smoothing(self, value: float):

        if len(self.__window) < self.__window_size:
            # filling window

            self.__window.append(value)
            return

        elif len(self.__window) == self.__window_size and not self.__start_cusum:
            # first time that the window is full

            self.__window.append(value)
            self.__window = self.__window[1:]

            self._smoothing.initialize(self.__window)

            mean = self._smoothing.get_smoothed_value()

            # calculating simga value
            square_sum = 0
            for val in self.__window:
                square_sum += (val - mean) ** 2

            self._sigma = math.sqrt(square_sum / self.__window_size)

            self.__start_cusum = True

        self.__window.append(value)
        self.__window = self.__window[1:]

        # calculating window mean
        window_mean = sum(self.__window) / self.__window_size

        print(window_mean)

        smoothing_factor = self._smoothing.get_smoothing_factor()

        # saving previous values of mu and sigma
        last_mu = self._smoothing.get_smoothed_value()
        last_sigma_square = self._sigma ** 2

        self._smoothing.forecast(window_mean)

        # calculating simga value
        self._sigma = math.sqrt(
            smoothing_factor * last_sigma_square +
            (1 - smoothing_factor) * (window_mean - last_mu) ** 2
        )

        self._z = window_mean - last_mu - 3*last_sigma_square

    def _cusum_detection(self):

        self._test_statistic = max(self._test_statistic + self._z, 0)

        if not self._under_attack:
            # checking violation
            if self._test_statistic > self._detection_threshold:
                print(f"{bcolors.FAIL}DoS attack detected{bcolors.ENDC}")
                self._under_attack = True

        else:
            if self._test_statistic <= self._detection_threshold and self._z < 0:
                # violation not detected
                print(f"{bcolors.OKGREEN}DoS ended{bcolors.ENDC}")
                self._test_statistic = 0
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
                 start_alarm_delay: int = 4,
                 stop_alarm_delay: int = 4,
                 window_size: int = 3,
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

        # time delay required for identifying the starting of an attack
        self.__start_alarm_delay = start_alarm_delay

        # maximum number of elements inside window
        self.__window_size = window_size
        # list of last self.__window_size elements
        self.__window = []

        # smoothing objects that implements the smoothing function
        self._smoothing = SingleExponentialSmoothing()

        # variance of values in window
        self._sigma = 0

        # once read self.__window_size values starts to apply cusum to new values
        self.__start_cusum = False

        # value used to calculate the test statistic
        self._z = 0

        # smoothing function for forecasting z values under attack
        self.__z_smoothing = DoubleExponentialSmoothing()

        # smoothing function for forecasting ewma values under attack
        self.__mu_smoothing = DoubleExponentialSmoothing()

        # saves last self.__stop_alarm_delay self._z values
        self.__z_values = []

        # saves last self.__stop_alarm_delay smoothed values
        self.__mu_values = []

        self.__start_ending_forecasting = False

        self.__start_abrupt_decrease_check = False

        # time delay required for identifying the ending of an attack
        self.__stop_alarm_delay = stop_alarm_delay

        # counts times that self.__z is negative after a certain time of attack detection
        self.__attack_ending_cum = 0

        # stores last value added in window
        self.__delta = 0

        # cumulates occurrences of abrupt decrease of next values stored in window
        self.__abrupt_decrease_cum = 0

    def _outlier_processing(self, value: float):

        if value > self.__outlier_threshold:
            # outlier threshold exceeded
            # the value is an outlier

            if not self._under_attack:
                # not already under attack

                self.__outlier_cum += 1

                if self.__outlier_cum == self.__start_alarm_delay:
                    # reached required times to detect an attack

                    print(f"{bcolors.FAIL}DoS attack detected{bcolors.ENDC}")
                    self.__outlier_cum -= 1
                    self.__z_values.append(self._z)
                    self._under_attack = True
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

            self._smoothing.initialize(self.__window)

            mean = self._smoothing.get_smoothed_value()

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

        print(window_mean)

        # saving previous values of mu and sigma
        last_mu = self._smoothing.get_smoothed_value()
        last_sigma_square = self._sigma ** 2

        # calculating window exponentially weighted moving average
        self._smoothing.forecast(window_mean)

        smoothing_factor = self._smoothing.get_smoothing_factor()

        # calculating simga value
        self._sigma = math.sqrt(
            smoothing_factor * last_sigma_square +
            (1 - smoothing_factor) * (window_mean - last_mu) ** 2
        )

        self._z = window_mean - last_mu - 3 * last_sigma_square

    def _cusum_detection(self):

        if not self.__start_cusum:
            return

        if not self._under_attack:

            self._test_statistic = max(self._test_statistic + self._z, 0)

            if self._z > 0:
                # adjusting detection threshold

                if self._detection_threshold == 0:
                    self._detection_threshold = self._z * self.__start_alarm_delay
                else:
                    self._detection_threshold = self._detection_threshold / 2 + \
                                                self._z * self.__start_alarm_delay / 2

                if self._test_statistic >= self._detection_threshold:
                    # under attack

                    print(f"{bcolors.FAIL}DoS attack detected{bcolors.ENDC}")
                    self._under_attack = True
                    self.__z_values.append(self._z)
            else:
                # not under attack and not necessity of threshold adjustment
                return
        else:

            self._test_statistic += self._z
            # under attack
            # checking end of an attack throughout sign of self.__z

            next_z_values = []
            next_mu_values = []

            if not self.__start_ending_forecasting:
                # updating self.__z_values

                if len(self.__z_values) < self.__stop_alarm_delay:
                    self.__z_values.append(self._z)
                    self.__mu_values.append(self._smoothing.get_smoothed_value())
                elif len(self.__z_values) == self.__stop_alarm_delay:
                    self.__z_smoothing.initialize(self.__z_values)
                    self.__mu_smoothing.initialize(self.__mu_values)
                    self.__z_values = []
                    self.__mu_values = []
                    self.__start_ending_forecasting = True
            else:
                self.__z_smoothing.forecast(self._z)
                self.__mu_smoothing.forecast(self._smoothing.get_smoothed_value())

                next_z_values = self.__z_smoothing.forecast_for(self.__stop_alarm_delay)
                next_mu_values = self.__mu_smoothing.forecast_for(self.__stop_alarm_delay)

                print("next_z_values: ", next_z_values)
                print("next_mu_values: ", next_mu_values)

                if all(i < j for i, j in zip(next_mu_values, next_mu_values[1:])):
                    # next values are all increasing (attack won't be stopped)

                    if any(n < 0 for n in next_z_values):
                        # z will be underestimated in next intervals
                        self.__start_abrupt_decrease_check = True

                if not self.__start_abrupt_decrease_check:
                    print("using z for ending check")
                    self.__check_ending_with_z()
                else:
                    print("using abrupt decrease check for ending check")
                    self.__check_abrupt_decrease()

    def __check_ending_with_z(self):
        if self._z <= 0:
            self.__attack_ending_cum += 1

            if self.__attack_ending_cum == self.__stop_alarm_delay:
                # reached required time delay before detect an attack ending

                self.__clear()

    def __check_abrupt_decrease(self):
        last_val = self.__window[-1]

        # checking abrupt decrease of new values
        if self.__delta == 0:
            self.__delta = last_val
        else:
            if self.__delta - last_val >= self.__delta:
                # got abrupt decrease

                self.__abrupt_decrease_cum += 1

                if self.__abrupt_decrease_cum == self.__stop_alarm_delay:
                    # detected end of attack

                    self.__clear()
            else:
                # updating self.__delta with exponentially weighted moving average method

                smoothing_factor = self._smoothing.get_smoothing_factor()
                self.__delta = smoothing_factor * self.__delta + (1 - smoothing_factor) * last_val

                if self.__abrupt_decrease_cum > 0:
                    self.__abrupt_decrease_cum -= 1

        print(str(self.__delta - last_val) + ">=" + str(self.__delta))

    def __clear(self):
        print(f"{bcolors.OKGREEN}DoS ended{bcolors.ENDC}")
        self._under_attack = False
        self.__abrupt_decrease_cum = 0
        self.__delta = 0
        self._test_statistic = 0
        self.__attack_ending_cum = 0
        self._detection_threshold = 0
        self.__start_ending_forecasting = False
        self.__start_abrupt_decrease_check = False

    def update(self, value: float):
        self._outlier_processing(value)
        self._data_smoothing(value)
        self._cusum_detection()

        return self._test_statistic


class SYNNPCusumDetector(NPCusumDetector):
    def __init__(self):
        super(SYNNPCusumDetector, self).__init__()

    def analyze(self, syn_count: int, synack_count: int):
        syn_value = 0.0

        if syn_count != 0:
            syn_value = float(syn_count - synack_count) / float(syn_count)

        syn_value = max(syn_value, 0)

        self.update(syn_value)
        print(f"{bcolors.OKCYAN}SYN Value: %.10f {bcolors.ENDC}" % syn_value)
        print(f"{bcolors.OKCYAN}SYN Zeta: {bcolors.ENDC}" + str(self._z))
        print(f"{bcolors.OKCYAN}SYN Sigma: {bcolors.ENDC}" + str(self._sigma))
        print(f"{bcolors.OKCYAN}SYN volume: {bcolors.ENDC}" + str(self._test_statistic))
        print(f"{bcolors.OKCYAN}SYN Mu: {bcolors.ENDC}" + str(self._smoothing.get_smoothed_value()))
        print(f"{bcolors.OKCYAN}SYN Threshold: {bcolors.ENDC}" + str(self._detection_threshold))
        print()

        return self._test_statistic, self._detection_threshold


class SYNCusumDetector(CusumDetector):
    def __init__(self, threshold=0.65):
        super().__init__(threshold=threshold)

    def analyze(self, syn_count: int, synack_count: int):
        syn_value = 0.0

        if syn_count != 0:
            syn_value = float(syn_count - synack_count) / float(syn_count)

        syn_value = max(syn_value, 0)

        self.update(syn_value)
        print(f"{bcolors.OKCYAN}SYN Value: %.10f {bcolors.ENDC}" % syn_value)
        print(f"{bcolors.OKCYAN}SYN Zeta: {bcolors.ENDC}" + str(self._z))
        print(f"{bcolors.OKCYAN}SYN Sigma: {bcolors.ENDC}" + str(self._sigma))
        print(f"{bcolors.OKCYAN}SYN volume: {bcolors.ENDC}" + str(self._test_statistic))
        print(f"{bcolors.OKCYAN}SYN Mu: {bcolors.ENDC}" + str(self._smoothing.get_smoothed_value()))
        print(f"{bcolors.OKCYAN}SYN Threshold: {bcolors.ENDC}" + str(self._detection_threshold))
        print()

        return self._test_statistic, self._detection_threshold
