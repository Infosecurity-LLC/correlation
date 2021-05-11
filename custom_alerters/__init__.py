from abc import ABC
from elastalert.alerts import Alerter
from elastalert.util import elastalert_logger
from soc_modules import processing


class SOCAlerter(Alerter, ABC):
    def __init__(self, rule):
        super(SOCAlerter, self).__init__(rule)

    def format_alert(self, result):
        alert = processing(self_params=self, data=result)
        return alert
