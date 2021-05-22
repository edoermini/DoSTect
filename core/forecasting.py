from scipy import optimize
import random
import sys
import numpy as np


class ExponentialSmoothing:

    def initialize(self, init_values: list, training_values: list):
        """
        Initializes smoothed value to given value for next iterations.

        :param training_values: the values used to estimate forecasting factors
        :param init_values: the list of init values
        """

        pass

    def get_smoothed_value(self) -> float:
        """
        Returns the calculated smoothed value
        """

        pass

    def forecast(self, value: float) -> float:
        """
        Applies exponential smoothing algorithm
        to forecast next value from given value and previous values

        :param value: the new value to do forecasting
        :return: forecasted value
        """

        pass


class SingleExponentialSmoothing(ExponentialSmoothing):

    def __init__(self, initial_smoothed_value=0):
        self.__smoothing_factor = random.random()

        self.__smoothed_value = initial_smoothed_value

    def __sse(self, values, smoothing_factor):

        self.__smoothing_factor = smoothing_factor

        print("SSE: ", self.__smoothing_factor)

        predictions = [values[0]]

        for value in values[1:]:
            predictions.append(self.forecast(value))

        try:
            s = 0
            for n, r in zip(values, predictions):
                s = s + (n - r) ** 2
            return s
        except OverflowError:
            return sys.float_info.max

    def initialize(self, init_values: list, training_values):
        self.__smoothed_value = init_values[0]

        forecasting_factors_init_guess = np.array([self.__smoothing_factor])

        bounds = ((0, 1),)
        loss_function = lambda x: self.__sse(init_values, x[0])

        forecasting_factors = optimize.minimize(
            loss_function,
            forecasting_factors_init_guess,
            method="SLSQP",
            bounds=bounds
        )

        self.__smoothing_factor = forecasting_factors.x[0]

        print("Final smoothing factor: ", self.__smoothing_factor)

    def get_smoothed_value(self) -> float:
        return self.__smoothed_value

    def forecast(self, value: float) -> float:
        self.__smoothed_value = self.__smoothing_factor * self.__smoothed_value + (1 - self.__smoothing_factor) * value

        return self.__smoothed_value


class DoubleExponentialSmoothing(ExponentialSmoothing):

    def __init__(self, initial_smoothed_value=0, initial_trend_value=0):
        self.__smoothing_factor = random.random()
        self.__trend_factor = random.random()

        self.__smoothed_value = initial_smoothed_value
        self.__trend_value = initial_trend_value

    def __sse(self, values, smoothing_factor, trend_factor):

        self.__smoothing_factor = smoothing_factor
        self.__trend_factor = trend_factor

        predictions = [values[0]]

        for value in values[1:]:
            predictions.append(self.forecast(value))

        try:
            s = 0
            for n, r in zip(values, predictions):
                s = s + (n - r) ** 2
            return s
        except OverflowError:
            return sys.float_info.max

    def initialize(self, init_values: list, training_values: list):
        """
        Initializes smoothed value to given value for next iterations.

        :param training_values: the values used to estimate forecasting factors
        :param init_values: the list of init values where values[0] is the initial smoothed value
        and values[1] is the initial trend value
        """

        self.__smoothed_value = init_values[0]
        self.__trend_value = init_values[1]

        forecasting_factors_init_guess = np.array([self.__smoothing_factor, self.__trend_factor])

        bounds = ((0, 1), (0, 1))
        loss_function = lambda x: self.__sse(init_values, x[0], x[1])

        forecasting_factors = optimize.minimize(
            loss_function,
            forecasting_factors_init_guess,
            method="SLSQP",
            bounds=bounds
        )

        self.__smoothing_factor = forecasting_factors.x[0]
        self.__trend_factor = forecasting_factors.x[1]

    def get_smoothed_value(self) -> float:
        """
        Returns the calculated smoothed value
        """

        return self.__smoothed_value + self.__trend_value

    def forecast(self, value: float) -> float:
        """
        Applies exponential smoothing algorithm
        to forecast next value from given value and previous values

        :param value: the new value to do forecasting
        :return: forecasted value
        """

        last_smoothed_value = self.__smoothed_value
        self.__smoothed_value = self.__smoothing_factor * value + \
                                (1 - self.__smoothing_factor) * (self.__smoothed_value + self.__trend_value)

        self.__trend_value = self.__trend_factor * (self.__smoothed_value - last_smoothed_value) + \
                             (1 - self.__trend_factor) * self.__trend_value

        return self.__smoothed_value + self.__trend_value
