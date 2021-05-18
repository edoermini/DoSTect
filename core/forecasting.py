import math


class NPCusum:
    def __init__(self):
        self.__test_statistic = 0

        self.__under_attack = False

        # the attack detection threshold used by cusum algorithm
        self.__detection_threshold = 0

        # a threshold for outlier identification
        self.__outlier_threshold = 0.65

        # accumulates the threshold violations
        self.__outlier_cum = 0

        # accumulates the alarming time
        self.__alarm_dur = 0

        # time delay required for identifying the starting of an attack
        self.__start_detection_delay = 7

        # maximum number of elements inside window
        self.__window_size = 3
        # list of last self.__window_size elements
        self.__window = []

        # exponentially weighted moving average factor
        self.__ewma_factor = 0.98

        # once read self.__window_size values starts to apply cusum to new values
        self.__start_cusum = False

        self.__mu = 0
        self.__sigma = 0

        # value used to calculate the test statistic
        self.__z = 0

        # time delay required for identifying the ending of an attack
        self.__end_detection_delay = 7

        # counts times that self.__z is negative after a certain time of attack detection
        self.__attack_ending_cum = 0

    def outlier_processing(self, value: float):

        if value > self.__outlier_threshold:
            # outlier threshold exceeded
            # the value is an outlier

            if not self.__under_attack:
                # not already under attack

                self.__outlier_cum += 1

                if self.__outlier_cum == self.__start_detection_delay:
                    # reached required times to detect an attack

                    print("DoS attack detected")
                    self.__outlier_cum = self.__start_detection_delay - 1
                    self.__under_attack = True
                    self.__alarm_dur += 1
            else:
                # already under attack

                self.__alarm_dur += 1

        else:
            # value is not an outlier

            if self.__outlier_cum > 0:
                self.__outlier_cum -= 1

    def data_smoothing(self, value: float):

        if len(self.__window) < self.__window_size:
            # filling window

            self.__window.append(value)
            return

        elif len(self.__window) == self.__window_size and not self.__start_cusum:
            # first time that the window is full

            self.__window.append(value)
            self.__window = self.__window[1:]

            # calculating mean value
            self.__mu = sum(self.__window) / self.__window_size

            # calculating simga value
            square_sum = 0
            for val in self.__window:
                square_sum += (val - self.__mu) ** 2
            self.__sigma = math.sqrt(square_sum / self.__window_size)

            self.__start_cusum = True

            return

        self.__window.append(value)
        self.__window = self.__window[1:]

        # calculating window mean
        window_mean = sum(self.__window) / self.__window_size

        # saving previous values of mu and sigma
        last_mu = self.__mu
        last_sigma = self.__sigma
        last_sigma_square = self.__sigma ** 2

        # calculating window exponentially weighted moving average
        self.__mu = self.__ewma_factor * last_mu + (1 - self.__ewma_factor) * window_mean

        # calculating simga value
        self.__sigma = math.sqrt(
            self.__ewma_factor * last_sigma_square +
            (1 - self.__ewma_factor) * (window_mean - last_mu) ** 2
        )

        print("Zeta: ", self.__z)
        print("Sigma: ", self.__sigma)
        print("Mu: ", self.__mu)

        self.__z = window_mean - last_mu - 3 * last_sigma_square

    def cusum_detection(self):

        if not self.__start_cusum:
            return

        self.__test_statistic = max(self.__test_statistic + self.__z, 0)

        if not self.__under_attack:

            if self.__z > 0:
                # adjusting detection threshold

                if self.__detection_threshold == 0:
                    self.__detection_threshold = self.__z * self.__start_detection_delay
                else:
                    self.__detection_threshold = self.__detection_threshold / 2 + \
                                                 self.__z * self.__start_detection_delay / 2

                if self.__test_statistic >= self.__detection_threshold:
                    # under attack

                    print("DoS attack detected")
                    self.__under_attack = True
                    self.__alarm_dur += 1
            else:
                # not under attack and not necessity of threshold adjustment
                return

        # checking end of an attack throughout sign of self.__z
        if self.__z <= 0:
            self.__attack_ending_cum += 1

            if self.__attack_ending_cum == self.__end_detection_delay:
                # reached required time delay before detect an attack ending

                print("DoS ended")
                self.__under_attack = False
                self.__test_statistic = 0
                self.__attack_ending_cum = 0
                self.__detection_threshold = 0

                if self.__alarm_dur < 6:
                    self.__alarm_dur = 0
            else:
                # continuing to raise alarm
                self.__alarm_dur += 1

    def update(self, value: float):
        print("Value: ", value)
        self.outlier_processing(value)
        self.data_smoothing(value)
        self.cusum_detection()

        return self.__test_statistic
