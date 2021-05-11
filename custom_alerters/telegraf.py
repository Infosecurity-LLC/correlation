from elastalert.alerts import Alerter
import time
import requests

class TelegrafAlerter(Alerter):
    """ Creates a Telegraf message for each alert in InfluxDB line protocol format"""
    required_options = frozenset(['telegraf_host', 'telegraf_port', 'name'])

    def alert(self, matches):
        if not isinstance(matches, dict) and not isinstance(matches, list):
            raise WrongAlertBody(f"Wrong message: {matches}")

        if isinstance(matches, dict):
            matches = [matches]

        def send_telegraf_message(_influxData):
            _time = int(float(time.time())*1000000000)
            _url = 'http://' + self.rule['telegraf_host'] + ':' + str(self.rule['telegraf_port']) + '/telegraf'
            _data = _influxData + ' ' + str(_time)
            _request = requests.post(url = _url, data = _data) 
        
        for body in matches:
            if self.rule['name'] == 'EAMON-RULE-RUNS':
                for _rule_name, _rule_count in body['top_events_rule_name'].items():
                    influx_data = 'elastalert_rule_runs,rule_name=' + _rule_name + ' rule_count=' + str(_rule_count)
                    send_telegraf = send_telegraf_message(influx_data)
            if self.rule['name'] == 'EAMON-ERRORS':
                _error_type = body['message'].split(':')[0]
                if "RULE-" in _error_type:
                    _error_type = _error_type.split('RULE-')[0]
                if "CORR-" in _error_type:
                    _error_type = _error_type.split('CORR-')[0]
                if "EAMON-" in _error_type:
                    _error_type = _error_type.split('EAMON-')[0]
                _error_type = _error_type.lower().replace(" ", "_")
                influx_data = 'elastalert_errors,error_type=' + _error_type + ' errors_count=1'
                send_telegraf = send_telegraf_message(influx_data)
