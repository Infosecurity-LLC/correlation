from elastalert.util import elastalert_logger
from custom_alerters import SOCAlerter
from elastalert import Elasticsearch
from dateutil import parser
import json
import datetime
import math
import numpy
import re

class ElasticSearchOffline(Exception):
    pass


class ElasticSearchSendError(Exception):
    pass


class WrongAlertBody(Exception):
    pass


class AVGTime(SOCAlerter):
    required_options = frozenset([
        'name',
        'out_es_host',
        'out_es_port',
        'out_es_index'
    ])
    
    def __init__(self, rule):
        super(AVGTime, self).__init__(rule)
        self.rule_name = self.rule['name']
        self.out_es_host = self.rule['out_es_host']
        self.out_es_port = self.rule['out_es_port']
        self.out_es_index = self.rule['out_es_index']
        self.ESInstance = self.prepare_elastic_client()

    def prepare_elastic_client(self) -> Elasticsearch:
        _es = None
        _es = Elasticsearch([{"host": self.out_es_host, "port": self.out_es_port}])
        if _es.ping():
            return _es
        raise ElasticSearchOffline(f"Could not connect to OUT ElasticSearch!: {self.out_es_host}:{self.out_es_port}")


    def alert(self, matches):
        def write_error_info_to_EA_service_index(_message, _problemField, _problemDoc, _ruleName):
            body = {
                "message": f'{_message}: {_problemField}',
                "traceback": f'{_problemDoc}',
                "data": {"rule": f'{_ruleName}'},
                "@timestamp": f'{datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}'
            }
            self.ESInstance.index(index='elastalert_status_error', doc_type='_doc', body=body)

        def filtering_not_user_accounts(_eventList: list):
            _filteredEventList = []
            _DWMPattern = re.compile("^DWM-[0-9]+$")
            _UMFDPattern = re.compile("^UMFD-[0-9]+$")
            for _event in _eventList:
                if not (_DWMPattern.match(_event['subject']['name'])
                        or _UMFDPattern.match(_event['subject']['name'])
                        or _event['subject']['name'][-1] == '$'):
                    _filteredEventList.append(_event)
            return _filteredEventList

        def get_time_list(_system, _period, _action, _organization, _domain, _username):
            _unicUserDocCount = 0
            _docID = ""
            _receivedTimeList = []
            _arrayFieldName = f'{_system}_{_period}_{_action}_time'
            _searchQuery = {
                "query": {
                    "query_string": {
                        "query": f'organization: "{_organization}" AND domain: "{_domain}" AND username: "{_username}"'
                    }
                }
            }
            _searchResult = self.ESInstance.search(index=self.out_es_index, body=_searchQuery)
            if isinstance(_searchResult['hits']['total'], dict):
                if 'value' in _searchResult['hits']['total']:
                    _unicUserDocCount = _searchResult['hits']['total']['value']
            elif isinstance(_searchResult['hits']['total'], int):
                _unicUserDocCount = _searchResult['hits']['total']
            if _unicUserDocCount > 0:
                for doc in _searchResult['hits']['hits']:
                    _docID = doc['_id']
                    if len(doc['_source'][_arrayFieldName]) > 0:
                        for _strTime in doc['_source'][_arrayFieldName]:
                            _receivedTimeList.append(datetime.datetime.strptime(_strTime, '%H:%M:%S').time())
            return _unicUserDocCount, _docID, _receivedTimeList

        def get_earlier_later_times(_eventList):
            _earlierTime = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
            _laterTime = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=365)
            for _event in _eventList:
                _eventDatetime = datetime.datetime.combine(datetime.date.today(), parser.parse(_event['@timestamp']).time()).replace(tzinfo=datetime.timezone.utc)
                if _eventDatetime < _earlierTime:
                    _earlierTime = _eventDatetime
                if _eventDatetime > _laterTime:
                    _laterTime = _eventDatetime
            return _earlierTime, _laterTime

        def time_to_radians(_time):
            _secondsFromMidnight = 3600 * _time.hour + 60 * _time.minute + _time.second
            _radians = float(_secondsFromMidnight) / float(24 * 60 * 60) * 2.0 * math.pi
            return _radians

        def average_angle(_angleList):
            x_sum = numpy.sum([math.sin(x) for x in _angleList])
            y_sum = numpy.sum([math.cos(x) for x in _angleList])
            x_mean = x_sum / float(len(_angleList))
            y_mean = y_sum / float(len(_angleList))
            return numpy.arctan2(x_mean, y_mean)

        def radians_to_time(_avgAngle):
            _secondsFromMidnight = int(float(_avgAngle) / (2.0 * math.pi) * 24.0 * 60.0 * 60.0)
            _hour = int((_secondsFromMidnight / 3600) % 24)
            _minute = int((_secondsFromMidnight % 3600) / 60)
            _second = int(_secondsFromMidnight % 60)
            return datetime.time(_hour, _minute, _second)

        def get_avg_of_times(_timeList):
            _angleList = [time_to_radians(_time) for _time in _timeList]
            _avgAngle = average_angle(_angleList)
            return radians_to_time(_avgAngle)

        if not isinstance(matches, dict) and not isinstance(matches, list):
            raise WrongAlertBody(f"Wrong message: {matches}")

        matches = filtering_not_user_accounts(matches)
        if len(matches) < 1:
            return
        
        first_event = matches[0]
        organization = first_event['collector']['organization']
        domain = first_event['subject']['domain']
        username = first_event['subject']['name']
        body_pattern = {
          "@timestamp": "null",
          "organization": "null",
          "domain": "null",
          "username": "null",
          "vpn_status": "null",
          "vpn_last_session_id": "null",
          "vpn_last_src_ip": "null",
          "vpn_last_src_country": "null",
          "vpn_early_start_time": [],
          "vpn_later_stop_time": [],
          "vpn_start_time_avg": "null",
          "vpn_stop_time_avg": "null",
          "win_status": "null",
          "win_last_logged_host": "null",
          "win_early_login_time": [],
          "win_later_logout_time": [],
          "win_login_time_avg": "null",
          "win_logout_time_avg": "null"
        }
        
        # Служебное правило по подсчету времен VPN подключения
        if "-VPN-GET-START-TIME" in self.rule_name:
            unic_user_doc_count, doc_id, vpn_early_start_time = get_time_list("vpn", "early", "start", organization, domain, username)
            if unic_user_doc_count > 1:
                write_error_info_to_EA_service_index("More than one uniq doc in vpn_win_correlation", f'{organization}|{domain}|{username}', json.dumps({'event': 'null'}), self.rule_name)
                return

            earlier_time_from_events, later_time_from_events = get_earlier_later_times(matches)
            
            if unic_user_doc_count == 0:
                body = body_pattern
                body['@timestamp'] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                body['organization'] = organization
                body['domain'] = domain
                body['username'] = username
                body['vpn_early_start_time'] = [ earlier_time_from_events.strftime("%H:%M:%S") ]
                body['vpn_start_time_avg'] = earlier_time_from_events.strftime("%H:%M:%S")
                self.ESInstance.index(index=self.out_es_index, doc_type='_doc', body=body)
            
            if unic_user_doc_count == 1:
                vpn_early_start_time.append(earlier_time_from_events.time())
                if len(vpn_early_start_time) > 1:
                    vpn_early_start_time = [vpn_early_start_time[-1]] + vpn_early_start_time[:-1]
                    if len(vpn_early_start_time) > 30:
                        vpn_early_start_time = vpn_early_start_time[0:30:1]
                avg_time = get_avg_of_times(vpn_early_start_time)
                vpn_early_start_time_str = [t.strftime("%H:%M:%S") for t in vpn_early_start_time]
                body = {
                    'doc': {
                        '@timestamp': f'{datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}',
                        'vpn_early_start_time': vpn_early_start_time_str,
                        'vpn_start_time_avg': avg_time.strftime("%H:%M:%S")
                    }
                }
                self.ESInstance.update(index=self.out_es_index, doc_type='_doc', id=doc_id, body=body)
        
        # Служебное правило по подсчету времен VPN отключения
        if "-VPN-GET-STOP-TIME" in self.rule_name:
            unic_user_doc_count, doc_id, vpn_later_stop_time = get_time_list("vpn", "later", "stop", organization, domain, username)
            if unic_user_doc_count > 1:
                write_error_info_to_EA_service_index("More than one uniq doc in vpn_win_correlation", f'{organization}|{domain}|{username}', json.dumps({'event': 'null'}), self.rule_name)
                return

            earlier_time_from_events, later_time_from_events = get_earlier_later_times(matches)
            
            if unic_user_doc_count == 0:
                body = body_pattern
                body['@timestamp'] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                body['organization'] = organization
                body['domain'] = domain
                body['username'] = username
                body['vpn_later_stop_time'] = [ later_time_from_events.strftime("%H:%M:%S") ]
                body['vpn_stop_time_avg'] = later_time_from_events.strftime("%H:%M:%S")
                self.ESInstance.index(index=self.out_es_index, doc_type='_doc', body=body)
            
            if unic_user_doc_count == 1:
                vpn_later_stop_time.append(later_time_from_events.time())
                if len(vpn_later_stop_time) > 1:
                    vpn_later_stop_time = [vpn_later_stop_time[-1]] + vpn_later_stop_time[:-1]
                    if len(vpn_later_stop_time) > 30:
                        vpn_later_stop_time = vpn_later_stop_time[0:30:1]
                avg_time = get_avg_of_times(vpn_later_stop_time)
                vpn_later_stop_time_str = [t.strftime("%H:%M:%S") for t in vpn_later_stop_time]
                body = {
                    'doc': {
                        '@timestamp': f'{datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}',
                        'vpn_later_stop_time': vpn_later_stop_time_str,
                        'vpn_stop_time_avg': avg_time.strftime("%H:%M:%S")
                    }
                }
                self.ESInstance.update(index=self.out_es_index, doc_type='_doc', id=doc_id, body=body)

        # Служебное правило по подсчету времен авторизации на Windows
        if self.rule_name == "CORR-MSWINDOWS-GET-LOGIN-TIME":
            unic_user_doc_count, doc_id, win_early_login_time = get_time_list("win", "early", "login", organization, domain, username)
            if unic_user_doc_count > 1:
                write_error_info_to_EA_service_index("More than one uniq doc in vpn_win_correlation", f'{organization}|{domain}|{username}', json.dumps({'event': 'null'}), self.rule_name)
                return

            earlier_time_from_events, later_time_from_events = get_earlier_later_times(matches)
            
            if unic_user_doc_count == 0:
                body = body_pattern
                body['@timestamp'] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                body['organization'] = organization
                body['domain'] = domain
                body['username'] = username
                body['win_early_login_time'] = [ earlier_time_from_events.strftime("%H:%M:%S") ]
                body['win_login_time_avg'] = earlier_time_from_events.strftime("%H:%M:%S")
                self.ESInstance.index(index=self.out_es_index, doc_type='_doc', body=body)
            
            if unic_user_doc_count == 1:
                win_early_login_time.append(earlier_time_from_events.time())
                if len(win_early_login_time) > 1:
                    win_early_login_time = [win_early_login_time[-1]] + win_early_login_time[:-1]
                    if len(win_early_login_time) > 30:
                        win_early_login_time = win_early_login_time[0:30:1]
                avg_time = get_avg_of_times(win_early_login_time)
                win_early_login_time_str = [t.strftime("%H:%M:%S") for t in win_early_login_time]
                body = {
                    'doc': {
                        '@timestamp': f'{datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}',
                        'win_early_login_time': win_early_login_time_str,
                        'win_login_time_avg': avg_time.strftime("%H:%M:%S")
                    }
                }
                self.ESInstance.update(index=self.out_es_index, doc_type='_doc', id=doc_id, body=body)
        
        # Служебное правило по подсчету времен выхода из системы Windows
        if self.rule_name == "CORR-MSWINDOWS-GET-LOGOUT-TIME":
            unic_user_doc_count, doc_id, win_later_logout_time = get_time_list("win", "later", "logout", organization, domain, username)
            if unic_user_doc_count > 1:
                write_error_info_to_EA_service_index("More than one uniq doc in vpn_win_correlation", f'{organization}|{domain}|{username}', json.dumps({'event': 'null'}), self.rule_name)
                return

            earlier_time_from_events, later_time_from_events = get_earlier_later_times(matches)
            
            if unic_user_doc_count == 0:
                body = body_pattern
                body['@timestamp'] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                body['organization'] = organization
                body['domain'] = domain
                body['username'] = username
                body['win_later_logout_time'] = [ later_time_from_events.strftime("%H:%M:%S") ]
                body['win_logout_time_avg'] = later_time_from_events.strftime("%H:%M:%S")
                self.ESInstance.index(index=self.out_es_index, doc_type='_doc', body=body)
            
            if unic_user_doc_count == 1:
                win_later_logout_time.append(later_time_from_events.time())
                if len(win_later_logout_time) > 1:
                    win_later_logout_time = [win_later_logout_time[-1]] + win_later_logout_time[:-1]
                    if len(win_later_logout_time) > 30:
                        win_later_logout_time = win_later_logout_time[0:30:1]
                avg_time = get_avg_of_times(win_later_logout_time)
                win_later_logout_time_str = [t.strftime("%H:%M:%S") for t in win_later_logout_time]
                body = {
                    'doc': {
                        '@timestamp': f'{datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}',
                        'win_later_logout_time': win_later_logout_time_str,
                        'win_logout_time_avg': avg_time.strftime("%H:%M:%S")
                    }
                }
                self.ESInstance.update(index=self.out_es_index, doc_type='_doc', id=doc_id, body=body)

    def get_info(self):
        return {
            'type': 'elasticsearch',
            'out_es': f'{self.out_es_host}:{self.out_es_port}',
            'index': self.out_es_index,
        }
