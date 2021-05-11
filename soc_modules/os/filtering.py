import re
import ntpath
from soc_modules.helpers import getval
from dateutil import parser
from dateutil import tz
import json
import datetime
import math
import numpy

class OSFiltering:
    def __init__(self):
        pass

    @staticmethod
    def filtering_not_hidden_shared_folder(_selfParams, event_list: list):
        """Из массива со скорелированными событиями удаляет события,
        в object.name которых не указана скрытая расшаренная сетевая папка"""
        _hiddenSharedFolderPattern = re.compile("^\\\\\\\\\*\\\\[\w]+\$$")
        _filteredEventList = []
        for event in event_list:
            if _hiddenSharedFolderPattern.match(getval(_selfParams, event, "object.name")):
                _filteredEventList.append(event)
        return _filteredEventList

    @staticmethod
    def filtering_dwm_umfd_accounts(_selfParams, event_list: list):
        """Из массива со скорелированными событиями удаляет события,
        в subject.name которых указаны DWM-x и UMFD-x"""
        # DWM-x Desktop Window Manager
        _DWMPattern = re.compile("^DWM-[0-9]+$")
        # UMFD-x User Mode Driver Framework
        _UMFDPattern = re.compile("^UMFD-[0-9]+$")
        _filteredEventList = []
        for event in event_list:
            _subject_name = getval(_selfParams, event, "subject.name")
            if not (_DWMPattern.match(_subject_name) or _UMFDPattern.match(_subject_name)):
                _filteredEventList.append(event)
        return _filteredEventList

    @staticmethod
    def filtering_subject_system_accounts(_selfParams, event_list: list):
        """Из массива со скорелированными событиями удаляет события,
        в которых subject.name - системное УЗ"""
        _filteredEventList = []
        for event in event_list:
            _subject_name = getval(_selfParams, event, "subject.name")
            if not _subject_name.endswith('$'):
                _filteredEventList.append(event)
        return _filteredEventList

    @staticmethod
    def filtering_subject_and_object_system_accounts(_selfParams, event_list: list):
        """Из массива со скорелированными событиями удаляет события,
        в которых subject.name И object.name - системные УЗ"""
        _filteredEventList = []
        for event in event_list:
            if 'name' in event['subject'] and 'name' in event['object']:
                if event['subject']['name'][-1] == '$' and event['object']['name'][-1] == '$':
                    continue
            _filteredEventList.append(event)
        return _filteredEventList

    @staticmethod
    def filtering_not_different_subject_and_object(_selfParams, event_list: list):
        """Из массива со скорелированными событиями удаляет события,
        в которых subject.name и object.name - одинаковы"""
        _filteredEventList = []
        for event in event_list:
            if not getval(_selfParams, event, "subject.name") == getval(_selfParams, event, "object.name"):
                _filteredEventList.append(event)
        return _filteredEventList

    @staticmethod
    def filtering_not_in_list_gpo(_selfParams, event_list: list):
        """Из массива со скорелированными событиями удаляет события,
        если GUID или DN GPO в которых не прописаны в списке"""
        _filteredEventList = []
        with open('./lists/controlled_gpo_list.txt', 'r') as _f:
            _file = _f.read()
        _fileSet = set(_file.splitlines())
        for event in event_list:
            _organization = getval(_selfParams, event, "collector.organization")
            _GPOGUID = getval(_selfParams, event, "object.id")
            _GPODN = getval(_selfParams, event, "object.path")
            _compositeGUID = f'\'{_organization}\'|\'{_GPOGUID}\''.lower()
            _compositeDN = f'\'{_organization}\'|\'{_GPODN}\''.lower()
            if _compositeGUID in _fileSet or _compositeDN in _fileSet:
                _filteredEventList.append(event)
        return _filteredEventList

    @staticmethod
    def filtering_not_in_list_process(_selfParams, event_list: list):
        """Из массива со скорелированными событиями удаляет события,
        в которых имя процесса не прописан в списке"""
        _filteredEventList = []
        with open('./lists/monitored_app_list.txt', 'r') as _f:
            _file = _f.read()
        _fileSet = set(_file.splitlines())
        for event in event_list:
            _organization = getval(_selfParams, event, "collector.organization")
            _newProcessFileName = getval(_selfParams, event, "object.path")
            _compositeProcessName = f'\'{_organization}\'|\'{_newProcessFileName}\''.lower()
            if _compositeProcessName in _fileSet:
                _filteredEventList.append(event)
        return _filteredEventList

    @staticmethod
    def filtering_not_psexec_filenames(_selfParams, event_list: list):
        """Из массива со скорелированными событиями удаляет события,
        в которых имя файла не содержит PsExec и ее аналогов"""
        _filteredEventList = []
        _PsExecProcessPatternList = ["psexec.*", "winexec.*", "csexec.*", "paexec.*"]
        _PsExecServicePatternList = ["psexe.*", "winexe.*", "csexe.*", "paexe.*"]
        for event in event_list:
            # Event ID: "4688" - A new process has been created
            msg_id = getval(_selfParams, event, "data.msgId")
            if msg_id == "4688":
                _newProcessFileName = ntpath.basename(getval(_selfParams, event, "object.path")).lower()
                for _PsExecProcessPattern in _PsExecProcessPatternList:
                    if re.compile(_PsExecProcessPattern).match(_newProcessFileName):
                        _filteredEventList.append(event)
            # Event ID: "7045" - New Service was installed
            elif msg_id == "7045":
                _newServiceFileName = ntpath.basename(getval(_selfParams, event, "object.path")).lower()
                for _PsExecServicePattern in _PsExecServicePatternList:
                    if re.compile(_PsExecServicePattern).match(_newServiceFileName):
                        _filteredEventList.append(event)
        return _filteredEventList

    @staticmethod
    def filtering_not_cmd_password_search(_selfParams, event_list: list):
        """Из массива со скорелированными событиями удаляет события,
        в которых CommandLine в data.aux7 не содержит CMD комманд поиска паролей"""
        _filteredEventList = []
        _passwordSearchCMDProcessPatternList = [
            "find.*password.*", "dir.*pass.*", "dir.*vnc\.ini.*", "dir.*unattend\.xml.*",
            "dir.*sysprep\.xml.*", "dir.*sysprep\.inf.*", "reg.*query.*password.*",
            "reg.*query.*putty.*", ".*get-unattendedinstallfile.*", ".*get-webconfig.*",
            ".*get-applicationhost.*", ".*get-sitelistpassword.*", ".*get-cachedgpppassword.*",
            ".*get-registryautologon.*"
        ]
        for event in event_list:
            _newProcessCommandLine = getval(_selfParams, event, "data.aux7").lower()
            for _passwordSearchCMDProcessPattern in _passwordSearchCMDProcessPatternList:
                if re.compile(_passwordSearchCMDProcessPattern).match(_newProcessCommandLine):
                    _filteredEventList.append(event)
        return _filteredEventList

    @staticmethod
    def filtering_smbexecpy_service_install(_selfParams, event_list: list):
        """
        Оставляет только те события, которые подходят под условие правила.
        """
        _filteredEventList = []
        for event in event_list:
            if 'path' in event['object']:
                if event['object']['path'].endswith(r'\execute.bat'):
                    _filteredEventList.append(event)
        return _filteredEventList

    @staticmethod
    def filtering_malicious_service_installations(_selfParams, event_list: list):
        """
        Оставляет только те события, которые подходят под условие правила Malicious Service Installations.
        """
        _filteredEventList = []
        for event in event_list:
            _service_name = getval(_selfParams, event, "object.name").lower()
            _service_file_name = getval(_selfParams, event, "object.path").lower()

            if _service_name in ['wceservice', 'wce service', 'mssecsvc2.0']:
                _filteredEventList.append(event)
            elif (_service_name.startswith('pwdump')
                    or _service_name.startswith('gsecdump')
                    or _service_name.startswith('cachedump')):
                _filteredEventList.append(event)
            elif r'\paexec' in _service_file_name:
                _filteredEventList.append(event)
            elif _service_file_name.startswith('winexesvc.exe'):
                _filteredEventList.append(event)
            elif _service_file_name.endswith(r'\dumpsvc.exe'):
                _filteredEventList.append(event)
            elif ' net user ' in _service_file_name:
                _filteredEventList.append(event)
        return _filteredEventList

    @staticmethod
    def filtering_win_login_in_usual_time(_selfParams, _eventList: list):
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

        unic_user_doc_count, is_exist_both_times, doc_id, win_login_time_avg, win_logout_time_avg = get_avg_times(
            _selfParams.ESInstance, "win", "login", "logout", organization, domain, username)
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
            body['win_status'] = 'logged_in'
            body['win_last_logged_host'] = first_event['source']['ip']
            _selfParams.ESInstance.index(index='vpn_win_correlation', doc_type='_doc', body=body)

        if unic_user_doc_count == 1:
            body = {
                'doc': {
                    '@timestamp': datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    'win_status': 'logged_in',
                    'win_last_logged_host': first_event['source']['ip']
                }
            }
            _selfParams.ESInstance.update(index='vpn_win_correlation', doc_type='_doc', id=doc_id, body=body)

            if is_exist_both_times:
                first_time = (datetime.datetime.combine(datetime.date.today(),
                                                        win_login_time_avg) - datetime.timedelta(hours=delta_hours,
                                                                                                 minutes=delta_minutes,
                                                                                                 seconds=delta_seconds)).time()
                second_time = (datetime.datetime.combine(datetime.date.today(),
                                                         win_logout_time_avg) + datetime.timedelta(
                    hours=delta_hours, minutes=delta_minutes, seconds=delta_seconds)).time()
                for event in _eventList:
                    if not is_time_in_middle(first_time, second_time, parser.parse(event['@timestamp']).time()):
                        if is_alert_case_from_list('mon_win_time', organization, domain, username):
                            event['interaction'][
                                'reason'] = f'Anomaly, because usually start is {win_login_time_avg.strftime("%H:%M:%S")}(UTC), stop is {win_logout_time_avg.strftime("%H:%M:%S")}(UTC). Delta taken {str(datetime.timedelta(hours=delta_hours, minutes=delta_minutes, seconds=delta_seconds))}'
                            event_list_to_alert.append(event)
        return event_list_to_alert

    @staticmethod
    def filtering_detects_rubeus_hack_tool(_selfParams, event_list: list):
        """
        Оставляет только те события, которые подходят под условие правила Detects Rubeus Hack Tool.
        """
        _filteredEventList = []
        _indicators_list = [r' asreproast ',
                            r' dump /service:krbtgt ',
                            r' kerberoast ',
                            r' createnetonly /program:',
                            r' ptt /ticket:',
                            r' /impersonateuser:',
                            r' renew /ticket:',
                            r' asktgt /user:',
                            r' harvest /interval:'
                            ]
        for event in event_list:
            _new_process_name = getval(_selfParams, event, "object.path").lower()

            for _indicator in _indicators_list:
                if _indicator in _new_process_name:
                    _filteredEventList.append(event)
        return _filteredEventList

    @staticmethod
    def filtering_not_critical_unix_host(_selfParams, _eventsList: list):
        """
        Фильтрует те события, в которых eventSource.location.host не указан в списке unix_critical_hosts
        """
        _filteredEventList = []
        with open('./lists/unix_critical_hosts.txt', 'r') as _f:
            _file = _f.read().splitlines()
        _fileSet = set(_file)
        for event in _eventsList:
            _organization = getval(_selfParams, event, "collector.organization")
            _host = getval(_selfParams, event, "eventSource.location.host")
            _composite = f"'{_organization}'|'{_host}'".lower()
            if _composite in _fileSet:
                _filteredEventList.append(event)
        return _filteredEventList

    @staticmethod
    def filtering_authorized_unix_account(_selfParams, _eventsList: list):
        """Удалеяет предварительно сагрегированные по subject.id события, если для subject.id указано соответсвие
        eventSource.location.host в индексе unix_authorization
        """
        _filteredEventList = []
        if len(_eventsList) < 1:
            return _filteredEventList
        _ES = _selfParams.ESInstance
        _firstEvent = _eventsList[0]
        _organization = getval(_selfParams, _firstEvent, "collector.organization").lower()
        _host = getval(_selfParams, _firstEvent, "eventSource.location.host").lower()
        _subjectID = getval(_selfParams, _firstEvent, "subject.id")
        _docCount = 0
        _uidList = []
        _searchQuery = {
            "query": {
                "query_string": {
                    "query": f'organization: "{_organization}" AND (hostname: "{_host}" OR ipaddr: "{_host}")'
                }
            }
        }
        _searchResult = _ES.search(index='unix_authorization', body=_searchQuery)
        if isinstance(_searchResult['hits']['total'], dict):
            if 'value' in _searchResult['hits']['total']:
                _docCount = _searchResult['hits']['total']['value']
        elif isinstance(_searchResult['hits']['total'], int):
            _docCount = _searchResult['hits']['total']
        if _docCount > 0:
            for doc in _searchResult['hits']['hits']:
                _uidList.append(doc['_source']['uid'])
        if not _subjectID in _uidList:
            _filteredEventList = _eventsList
        return _filteredEventList

    @staticmethod
    def filtering_unix_account_in_allowed_time(_selfParams, _eventsList: list):
        """Удалеяет предварительно сагрегированные по субъекту события,
        если сейчас для субъекта разрешенное время
        """
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

        _filteredEventList = []
        if len(_eventsList) < 1:
            return _filteredEventList
        _toAlert = True
        _ES = _selfParams.ESInstance
        _firstEvent = _eventsList[0]
        _organization = getval(_selfParams, _firstEvent, "collector.organization").lower()
        _host = getval(_selfParams, _firstEvent, "eventSource.location.host").lower()
        _subjectID = getval(_selfParams, _firstEvent, "subject.id")
        _fromZone = tz.gettz('UTC')
        _toZone = tz.gettz('Europe/Moscow')
        _eventTime = parser.parse(_firstEvent['@timestamp']).replace(tzinfo=_fromZone).astimezone(_toZone).time()
        _docCount = 0
        _searchQuery = {
            "query": {
                "query_string": {
                    "query": f'organization: "{_organization}" AND (hostname: "{_host}" OR ipaddr: "{_host}") AND uid: "{_subjectID}"'
                }
            }
        }
        _searchResult = _ES.search(index='unix_authorization', body=_searchQuery)
        if isinstance(_searchResult['hits']['total'], dict):
            if 'value' in _searchResult['hits']['total']:
                _docCount = _searchResult['hits']['total']['value']
        elif isinstance(_searchResult['hits']['total'], int):
            _docCount = _searchResult['hits']['total']
        if _docCount > 0:
            _firstDoc = _searchResult['hits']['hits'][0]
            _startTime = datetime.datetime.strptime(_firstDoc['_source']['hour_start'], '%H:%M:%S').replace(tzinfo=_toZone).time()
            _endTime = datetime.datetime.strptime(_firstDoc['_source']['hour_end'], '%H:%M:%S').replace(tzinfo=_toZone).time()
            if is_time_in_middle(_startTime, _endTime, _eventTime):
                _toAlert = False
        if _toAlert:
            _filteredEventList = _eventsList
        return _filteredEventList


def filter_data(self_params, data: list):
    """
    Фильтрация данных для категории ОС
    :param self_params:
    :param data:
    :return:
    """
    correlation_rule_name = self_params.rule['name']
    osf = OSFiltering()

    filter_map = {
        'CORR-WINDOWS-HIDDEN-SHARED-FOLDER-ACCESS': [osf.filtering_not_hidden_shared_folder],
        'CORR-WINDOWS-LOGON-RESTRICTED-TIME': [osf.filtering_dwm_umfd_accounts],
        'CORR-MSWINDOWS-RESET-ACCOUNT-PASSWORD': [osf.filtering_subject_and_object_system_accounts],
        'CORR-MSWINDOWS-CHANGING-ACCOUNT-PASSWORD': [osf.filtering_not_different_subject_and_object],
        'CORR-MSWINDOWS-GPO-CHANGED': [osf.filtering_not_in_list_gpo],
        'CORR-MSWINDOWS-MONITORED-PROCESS-CREATED': [osf.filtering_not_in_list_process],
        'CORR-MSWINDOWS-RUNNING-PSEXEC': [osf.filtering_not_psexec_filenames],
        'CORR-MSWINDOWS-OBJECT-FORBIDDEN-ACCESS-RESTRICTED-TIME': [osf.filtering_subject_system_accounts],
        'CORR-MSWINDOWS-USER-ADDED-TO-LOCAL-ADMINISTRATORS': [osf.filtering_subject_system_accounts],
        'CORR-MSWINDOWS-CMD-PASSWORD-SEARCH': [osf.filtering_not_cmd_password_search],
        'CORR-MSWINDOWS-SMBEXECPY-SERVICE-INSTALLATION': [osf.filtering_smbexecpy_service_install],
        'CORR-MSWINDOWS-BRUTE-FORCE-ACCOUNT': [osf.filtering_subject_system_accounts],
        'CORR-MSWINDOWS-BRUTE-FORCE-PASSWORD-SPRAYING': [osf.filtering_subject_system_accounts],
        'CORR-MSWINDOWS-BRUTE-FORCE-ACCOUNT-NTLM': [osf.filtering_subject_system_accounts],
        'CORR-MSWINDOWS-BRUTE-FORCE-ACCOUNT-KRB': [osf.filtering_subject_system_accounts],
        'CORR-MSWINDOWS-MALICIOUS-SERVICE-INSTALLATIONS': [osf.filtering_malicious_service_installations],
        'CORR-MSWINDOWS-LOGIN-ANOMALY-TIME': [osf.filtering_subject_system_accounts, osf.filtering_dwm_umfd_accounts, osf.filtering_win_login_in_usual_time],
        'CORR-MSWINDOWS-DETECTS-RUBEUS-HACK-TOOL': [osf.filtering_detects_rubeus_hack_tool],
        'CORR-AUDITD-LOGIN-UNAUTHORIZED-ACCOUNT-ON-CRITICAL-HOST': [osf.filtering_not_critical_unix_host, osf.filtering_authorized_unix_account],
        'CORR-AUDITD-LOGIN-RESTRICTED-TIME-ON-CRITICAL-HOST': [osf.filtering_not_critical_unix_host, osf.filtering_unix_account_in_allowed_time],
        'CORR-AUDITD-ADD-USER-ON-CRITICAL-HOST': [osf.filtering_not_critical_unix_host],
        'CORR-AUDITD-DEL-USER-ON-CRITICAL-HOST': [osf.filtering_not_critical_unix_host]
    }
    filtered_data = data
    if correlation_rule_name in filter_map.keys():
        for filter_method in filter_map[correlation_rule_name]:
            filtered_data = filter_method(self_params, filtered_data)
        return filtered_data
    else:
        return data
