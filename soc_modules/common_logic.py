from soc_modules.helpers import getval
from datetime import datetime
import json


class ItemDoesNotExist(Exception):
    pass


class CommonLogic:
    def __init__(self):
        pass

    @staticmethod
    def prepare_keys_for_deleting(rule):
        keys_for_del = ['num_matches', 'num_hits', '_type', '_index', '_id']

        if 'aggregation_key' in rule:
            if isinstance(rule['aggregation_key'], list):
                aggregation_keys = rule['aggregation_key']
            else:
                aggregation_keys = [rule['aggregation_key']]
            aggregation_keys_str = ','.join(aggregation_keys)
            keys_for_del.append(aggregation_keys_str)

        if 'query_key' in rule:
            if isinstance(rule['query_key'], list):
                query_keys = rule['query_key']
            else:
                query_keys = [rule['query_key']]
            query_keys_str = ','.join(query_keys)
            keys_for_del.append(query_keys_str)
        return keys_for_del

    @staticmethod
    def clear_stuff_items(_message: dict, del_words: list = None):
        """ Удаление из события служебных полей """
        if not del_words:
            return _message

        def clear_normalized_event(_mess, _words):
            for w in _words:
                try:
                    del _mess[w]
                except KeyError:
                    pass
            return _mess

        if 'category' not in _message or not _message['category']:
            raise ItemDoesNotExist(f"Event {_message.get('_id')} has not 'category' item")

        _message = clear_normalized_event(_message, del_words)
        return _message

    @staticmethod
    def get_ids_norm_events(event_list: list, limit: int = 10):
        _eventIds = []
        _rawIds = []
        for event in event_list:
            if len(_eventIds) < limit:
                _eventIds.append(event['id'])
                for rawid in event['data']['rawIds']:
                    if len(_rawIds) < limit:
                        _rawIds.append(rawid)
        return _eventIds, _rawIds, len(event_list)

    @staticmethod
    def get_corr_severity_level(correlation_list: list, final_corr_rule_name):
        # Минимальный уровень важности д/б LOW
        _severityLevelId = 1
        _severityLevel = ""
        _permittedImportanceLevelList = ['INFO', 'LOW', 'MEDIUM', 'HIGH']
        importance_level = {
            'INFO': 0,
            'LOW': 1,
            'MEDIUM': 2,
            'HIGH': 3
        }
        for correlation in correlation_list:
            if correlation['interaction']['importance'] in _permittedImportanceLevelList:
                if importance_level[correlation['interaction']['importance']] > _severityLevelId:
                    _severityLevelId = importance_level[correlation['interaction']['importance']]
        if "NOTNEUTRALIZED" in final_corr_rule_name.split("-"):
            if "SPECIAL" in final_corr_rule_name.split("-"):
                _severityLevelId = 3
            else:
                if _severityLevelId < 2:
                    _severityLevelId = 2
        for _value, _id in importance_level.items():
            if _id == _severityLevelId:
                _severityLevel = _value
        return _severityLevel

    @staticmethod
    def get_rule_name_for_crit_hosts(events: list, _selfParams, original_corr_rule_name) -> str:
        """Генерирует новое имя для правила корреляции, с целью определения,
        является ли хост критичным или нет"""
        _is_included = False
        with open('./lists/critical_hosts.txt', 'r') as f:
            _file = f.read().splitlines()
        _file_set = set(_file)
        for event in events:
            _organization = getval(_selfParams, event, "collector.organization")
            _host_ip = getval(_selfParams, event, "eventSource.location.ip")
            _hostname = getval(_selfParams, event, "eventSource.location.hostname")
            _composite_ip = _organization + _host_ip
            _composite_hostname = _organization + _hostname

            if _composite_hostname in _file_set:
                _is_included = True
            elif _composite_ip in _file_set:
                _is_included = True

        if _is_included:
            _new_corr_rule_name = original_corr_rule_name + '-ON-CRITICAL-HOST'
        else:
            _new_corr_rule_name = original_corr_rule_name + '-ON-NON-CRITICAL-HOST'
        return _new_corr_rule_name

    def get_rule_name_for_allowed_accounts_windows(self, events: list, _self_params, correlation_rule_name):
        """Генерирует новое имя для правила корреляции, с целью определения,
        разрешена ли авторизация конкретной УЗ на критичном хосте"""
        rule_name = self.get_rule_name_for_crit_hosts(events, _self_params, correlation_rule_name)
        if '-ON-CRITICAL-HOST' in rule_name:
            with open('./lists/allowed_accounts_windows.txt', 'r') as f:
                file = f.read().splitlines()
            file_set = set(file)

            for event in events:
                _organization = getval(_self_params, event, "collector.organization")
                _host_ip = getval(_self_params, event, "eventSource.location.ip")
                _user_domain = getval(_self_params, event, "subject.domain")
                _username = getval(_self_params, event, "subject.name")
                _logon_type = getval(_self_params, event, "interaction.logonType")
                _composite = f'{_organization}{_host_ip}{_user_domain}{_username}{_logon_type}'.lower()
                if _composite not in file_set:
                    _new_corr_rule_name = correlation_rule_name + '-UNAUTHORIZED-ACCOUNT'
                    return _new_corr_rule_name
        else:
            return

    @staticmethod
    def get_rule_name_for_allowed_accounts_network(events: list, _selfParams, correlation_rule_name):
        """Генерирует новое имя для правила корреляции, с целью определения,
        разрешена ли авторизация конкретной УЗ на критичном хосте сетевого оборудования"""
        with open('./lists/allowed_accounts_network.txt', 'r') as f:
            _file = f.read()
        _file_set = set(_file.splitlines())

        for event in events:
            _organization = getval(_selfParams, event, "collector.organization")
            _host_ip = getval(_selfParams, event, "eventSource.location.ip")
            _username = getval(_selfParams, event, "subject.name")
            _composite_host = f'{_organization}{_host_ip}'.lower()
            _composite_user = f'{_organization}{_host_ip}{_username}'.lower()
            if _composite_host in _file:
                if _composite_user not in _file_set:
                    _new_corr_rule_name = correlation_rule_name + '-UNAUTHORIZED-ACCOUNT'
                    # Инцидент, т.к. данному пользователю не разрешена авторизация на данный хост
                    return _new_corr_rule_name
        return  # Данный хост не критичный или пользователю разрешена атворизация на данный хост

    @staticmethod
    def get_rule_name_for_critical_groups_windows(events: list, _selfParams, original_corr_rule_name) -> str:
        """Генерирует новое имя для правила корреляции, с целью определения,
        критичная ли это windows группа"""
        with open('./lists/critical_groups_windows.txt', 'r') as f:
            _file = f.read().splitlines()
        _file_set = set(_file)
        for event in events:
            _organization = getval(_selfParams, event, "collector.organization")
            _domain = getval(_selfParams, event, "object.domain")
            _group_name = getval(_selfParams, event, "object.name")
            _composite = f'{_organization}{_domain}{_group_name}'.lower()
            if _composite in _file_set:
                _new_corr_rule_name = original_corr_rule_name + '-FROM-CRITICAL-LIST'
                return _new_corr_rule_name

        return original_corr_rule_name


def common_logic(self_params, data: list, correlation_rule_name):
    """
    Обработка данных общая для любых событий, независимо от продукта
    :param self_params
    :param data:
    :param correlation_rule_name:
    :return: json
    """
    cl = CommonLogic()
    keys_for_del = cl.prepare_keys_for_deleting(self_params.rule)

    if 'list' in self_params.rule:
        if self_params.rule['list'] == 'critical_hosts':
            correlation_rule_name = cl.get_rule_name_for_crit_hosts(data, self_params, correlation_rule_name)
        elif self_params.rule['list'] == 'allowed_accounts_windows':
            # TODO: подумать, как это отсюда красиво вынести
            correlation_rule_name = cl.get_rule_name_for_allowed_accounts_windows(data, self_params, correlation_rule_name)
            if not correlation_rule_name:
                return
        elif self_params.rule['list'] == 'allowed_accounts_network':
            correlation_rule_name = cl.get_rule_name_for_allowed_accounts_network(data, self_params, correlation_rule_name)
            if not correlation_rule_name:
                return
        elif self_params.rule['list'] == 'critical_groups_windows':
            # TODO: подумать, как это отсюда красиво вынести
            correlation_rule_name = cl.get_rule_name_for_critical_groups_windows(data, self_params, correlation_rule_name)

    alert = data[0]
    alert = cl.clear_stuff_items(alert, keys_for_del)
    event_ids, raw_ids, event_count = cl.get_ids_norm_events(data, 10)
    if 'severity' in self_params.rule:
        corr_severity_level = self_params.rule['severity']
    else:
        corr_severity_level = cl.get_corr_severity_level(data, correlation_rule_name)

    alert.update({'@timestamp': datetime.now().astimezone().isoformat()})
    alert.update({'category': 'Correlated'})
    alert.update({'correlation': {'eventIds': event_ids,
                                  'count': event_count,
                                  'name': correlation_rule_name,
                                  'type': ""}
                  })
    alert.update({'eventTime': datetime.now().strftime("%s")})
    alert['interaction']['importance'] = corr_severity_level
    alert['data']['rawIds'] = raw_ids

    return json.dumps(alert)
