
class AbstractDetector(object):

    def __init__(self):
        self.results_ = []

    def check(self):
        raise NotImplementedError("Detector must implement check()")

    @property
    def results(self):
        return self.results_