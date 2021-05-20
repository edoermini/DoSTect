class ExponentialSmoothing:

    def forecast(self, value: float) -> float:
        """
        Applies exponential smoothing algorithm
        to forecast next value from given value and previous values

        :param value: the new value to do forecasting
        :return: forecasted value
        """

        pass


class SingleExponentialSmoothing(ExponentialSmoothing):

    def __init__(self, initial_smoothed_value, ewma_factor=0.98):
        self.ewma_factor = ewma_factor
        self.smoothed_value = initial_smoothed_value

    def forecast(self, value: float) -> float:
        self.smoothed_value = self.__ewma_factor * self.smoothed_value + (1 - self.__ewma_factor) * value

        return self.smoothed_value

