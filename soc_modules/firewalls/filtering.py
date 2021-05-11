from soc_modules.helpers import getval
from dateutil import parser
import json
import datetime
import math
import numpy

class FWFiltering:
    def __init__(self):
        pass

    @staticmethod
    def filtering_legal_admin_activity_on_fortigate(_selfParams, event_list: list):
        """Из массива со скорелированными событиями удаляет события
        с легитимной активностью админ. УЗ при выполнении команд на Fortigate"""
        _filteredEventList = []
        _eventIdWithObjectList = [
            "0100044544", "0100044545", "0100044546", "0100044547",
            "0100044548", "0100044549", "0100044550", "0100044551",
            "0100044552"
        ]
        # 0100044544 - Path configured
        # 0100044545 - Object configured
        # 0100044546 - Attribute configured
        # 0100044547 - Object attribute configured
        # 0100044548 - Action performed
        # 0100044549 - Object attribute configured by maintainer
        # 0100044550 - Object configured by maintainer
        # 0100044551 - Attribute configured by maintainer
        # 0100044552 - Path configured by maintainer
        with open('./lists/fortigate_superadmins.txt', 'r') as _fSuper:
            _fileSuper = _fSuper.read()
        _fileSetSuper = set(_fileSuper.splitlines())
        with open('./lists/fortigate_admin_forbidden_actions.txt', 'r') as _fForbidden:
            _fileForbidden = _fForbidden.read()
        _fileSetForbidden = set(_fileForbidden.splitlines())
        with open('./lists/fortigate_admin_allowed_actions.txt', 'r') as _fAllowed:
            _fileAllowed = _fAllowed.read()
        _fileSetAllowed = set(_fileAllowed.splitlines())
        for event in event_list:
            _organization = getval(_selfParams, event, "collector.organization")
            _device = getval(_selfParams, event, "eventSource.location.ip")
            _userName = getval(_selfParams, event, "subject.name")
            _eventId = getval(_selfParams, event, "data.msgId")
            _compositeSuperAdmin = f'\'{_organization}\'|\'{_device}\'|\'{_userName}\''.lower()
            if _compositeSuperAdmin not in _fileSetSuper:
                if _eventId in _eventIdWithObjectList:
                    _object = event['data']['aux1'].split(' ')[1]
                    _compositeWithObject = f'\'{_organization}\'|\'{_device}\'|\'{_userName}\'|\'{_eventId}\'|\'{_object}\''.lower()
                    if (_compositeWithObject in _fileSetForbidden or
                            _compositeWithObject not in _fileSetAllowed):
                        _filteredEventList.append(event)
                else:
                    _compositeWithoutObject = f'\'{_organization}\'|\'{_device}\'|\'{_userName}\'|\'{_eventId}\'|\'\''.lower()
                    if (_compositeWithoutObject in _fileSetForbidden or
                            _compositeWithoutObject not in _fileSetAllowed):
                        _filteredEventList.append(event)
        return _filteredEventList


    @staticmethod
    def filtering_vpn_connection_in_usual_time(_selfParams, _eventList: list):
        def get_avg_times(_ES, _system, _actionFirst, _actionSecond, _organization, _domain, _username):
            _unicUserDocCount = 0
            _isExistBothTimes = False
            _docID = ""
            _firstTimeStr = "null"
            _secondTimeStr = "null"
            _firstTime = "null"
            _secondTime = "null"
            _firstTimeFieldName = f'{_system}_{_actionFirst}_time_avg'
            _secondTimeFieldName = f'{_system}_{_actionSecond}_time_avg'
            _searchQuery = {
                "query": {
                    "query_string": {
                        "query": f'organization: "{_organization}" AND domain: "{_domain}" AND username: "{_username}"'
                    }
                }
            }
            _searchResult = _ES.search(index='vpn_win_correlation', body=_searchQuery)
            if isinstance(_searchResult['hits']['total'], dict):
                if 'value' in _searchResult['hits']['total']:
                    _unicUserDocCount = _searchResult['hits']['total']['value']
            elif isinstance(_searchResult['hits']['total'], int):
                _unicUserDocCount = _searchResult['hits']['total']
            if _unicUserDocCount > 0:
                for doc in _searchResult['hits']['hits']:
                    _docID = doc['_id']
                    if doc['_source'][_firstTimeFieldName] != "null":
                        _firstTimeStr = doc['_source'][_firstTimeFieldName]
                    if doc['_source'][_secondTimeFieldName] != "null":
                        _secondTimeStr = doc['_source'][_secondTimeFieldName]
            if _firstTimeStr != "null" and _secondTimeStr != "null":
                _isExistBothTimes = True
                _firstTime = datetime.datetime.strptime(_firstTimeStr, '%H:%M:%S').time()
                _secondTime = datetime.datetime.strptime(_secondTimeStr, '%H:%M:%S').time()
            return _unicUserDocCount, _isExistBothTimes, _docID, _firstTime, _secondTime

        def write_error_info_to_EA_service_index(_ES, _message, _problemField, _problemDoc, _ruleName):
            body = {
                "message": f'{_message}: {_problemField}',
                "traceback": f'{_problemDoc}',
                "data": {"rule": f'{_ruleName}'},
                "@timestamp": f'{datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}'
            }
            _ES.index(index='elastalert_status_error', doc_type='_doc', body=body)

        def is_alert_case_from_list(_listName, _organization, _domain, _username):
            _isAlertCase = False
            with open(f'./lists/{_listName}.txt', 'r') as _f:
                _file = _f.read()
            _fileSet = set(_file.splitlines())
            _whiteListKeys = []
            _whiteListKeys.append(f'\'{_organization}\'|\'\'|\'\'|\'true\''.lower())
            _whiteListKeys.append(f'\'{_organization}\'|\'{_domain}\'|\'\'|\'true\''.lower())
            _whiteListKeys.append(f'\'{_organization}\'|\'{_domain}\'|\'{_username}\'|\'true\''.lower())
            for _whiteKey in _whiteListKeys:
                if _whiteKey in _fileSet:
                    _isAlertCase = True
            _blackListKeys = []
            _blackListKeys.append(f'\'{_organization}\'|\'\'|\'\'|\'false\''.lower())
            _blackListKeys.append(f'\'{_organization}\'|\'{_domain}\'|\'\'|\'false\''.lower())
            _blackListKeys.append(f'\'{_organization}\'|\'{_domain}\'|\'{_username}\'|\'false\''.lower())
            for _blackKey in _blackListKeys:
                if _blackKey in _fileSet:
                    _isAlertCase = False
            return _isAlertCase

        def time_to_radians(_time):
            _secondsFromMidnight = 3600 * _time.hour + 60 * _time.minute + _time.second
            _radians = float(_secondsFromMidnight) / float(24 * 60 * 60) * 2.0 * math.pi
            return _radians

        def is_time_in_middle(_firstTime, _secondTime, _comparableTime):
            _isTimeInMiddle = False
            _midnightTimeMin = datetime.time(hour=0, minute=0, second=0)
            _midnightTimeMax = datetime.time(hour=23, minute=59, second=59)
            if _firstTime < _secondTime:
                if _firstTime < _comparableTime < _secondTime:
                    _isTimeInMiddle = True
            else:
                if _firstTime < _comparableTime <= _midnightTimeMax or _midnightTimeMin <= _comparableTime < _secondTime:
                    _isTimeInMiddle = True
            return _isTimeInMiddle

        event_list_to_alert = []
        if len(_eventList) < 1:
            return event_list_to_alert
        is_exist_both_times = False
        delta_hours = 2  # 0-23
        delta_minutes = 0  # 0-59
        delta_seconds = 0  # 0-59
        first_event = _eventList[0]
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

        unic_user_doc_count, is_exist_both_times, doc_id, vpn_start_time_avg, vpn_stop_time_avg = get_avg_times(
            _selfParams.ESInstance, "vpn", "start", "stop", organization, domain, username)
        if unic_user_doc_count > 1:
            write_error_info_to_EA_service_index(_selfParams.ESInstance, "More than one uniq doc in vpn_win_correlation",
                                                 f'{organization}|{domain}|{username}',
                                                 json.dumps({'event': 'null'}), _selfParams.rule['name'])
            return event_list_to_alert

        if unic_user_doc_count == 0:
            body = body_pattern
            body['@timestamp'] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            body['organization'] = organization
            body['domain'] = domain
            body['username'] = username
            body['vpn_status'] = 'connected'
            body['vpn_last_src_ip'] = first_event['source']['ip']
            body['vpn_last_src_country'] = first_event['source']['enrichment']['geo']['country']
            _selfParams.ESInstance.index(index='vpn_win_correlation', doc_type='_doc', body=body)

        if unic_user_doc_count == 1:
            body = {
                'doc': {
                    '@timestamp': datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    'vpn_status': 'connected',
                    'vpn_last_src_ip': first_event['source']['ip'],
                    'vpn_last_src_country': first_event['source']['enrichment']['geo']['country']
                }
            }
            _selfParams.ESInstance.update(index='vpn_win_correlation', doc_type='_doc', id=doc_id, body=body)

            if is_exist_both_times:
                first_time = (datetime.datetime.combine(datetime.date.today(),
                                                        vpn_start_time_avg) - datetime.timedelta(hours=delta_hours,
                                                                                                 minutes=delta_minutes,
                                                                                                 seconds=delta_seconds)).time()
                second_time = (datetime.datetime.combine(datetime.date.today(),
                                                         vpn_stop_time_avg) + datetime.timedelta(hours=delta_hours,
                                                                                                 minutes=delta_minutes,
                                                                                                 seconds=delta_seconds)).time()
                for event in _eventList:
                    if not is_time_in_middle(first_time, second_time, parser.parse(event['@timestamp']).time()):
                        if is_alert_case_from_list('mon_vpn_time', organization, domain, username):
                            event['interaction'][
                                'reason'] = f'Anomaly, because usually start is {vpn_start_time_avg.strftime("%H:%M:%S")}(UTC), stop is {vpn_stop_time_avg.strftime("%H:%M:%S")}(UTC). Delta taken {str(datetime.timedelta(hours=delta_hours, minutes=delta_minutes, seconds=delta_seconds))}'
                            event_list_to_alert.append(event)
        return event_list_to_alert


def filter_data(self_params, data: list):
    """
    Фильтрация данных
    :param self_params:
    :param data:
    :return:
    """
    correlation_rule_name = self_params.rule['name']
    fwf = FWFiltering()
    filter_map = {
        'CORR-FORTIGATE-ILLEGAL-ADMIN-ACTIVITY': [fwf.filtering_legal_admin_activity_on_fortigate],
        'CORR-FORTIGATE-VPN-START-ANOMALY-TIME': [fwf.filtering_vpn_connection_in_usual_time]
    }
    filtered_data = data
    if correlation_rule_name in filter_map.keys():
        for filter_method in filter_map[correlation_rule_name]:
            filtered_data = filter_method(self_params, filtered_data)
        return filtered_data
    else:
        return data
