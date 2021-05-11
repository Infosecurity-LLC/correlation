from soc_modules.os import filter_data as filter_data_os, apply_logic as apply_logic_os
from soc_modules.antiviruses import filter_data as filter_data_av, apply_logic as apply_logic_av
from soc_modules.firewalls import filter_data as filter_data_fw, apply_logic as apply_logic_fw
from soc_modules.common_logic import common_logic
import soc_modules.helpers

filter_map = {
    "windows": filter_data_os,
    "linux": filter_data_os,
    "auditd": filter_data_os,
    "kaspersky": filter_data_av,
    "symantec": filter_data_av,
    "antiviruses": filter_data_av,
    "nod32": filter_data_av,
    "fortigate": filter_data_fw,
    "ciscoasa": filter_data_fw
    # ... TODO: тут заполнить по требованиям к обработке
}
logic_map = {
    "kaspersky": apply_logic_av,
    "symantec": apply_logic_av,
    "antiviruses": apply_logic_av,
    "nod32": apply_logic_av,
    "windows": apply_logic_os,
    "auditd": apply_logic_os,
    "fortigate": apply_logic_fw,
    "ciscoasa": apply_logic_fw
    # ... TODO: тут заполнить по требованиям к обработке
}


def processing(self_params, data):
    def filtering(_self_params, _data: list):
        """
        Фильтрация
        :param _self_params:
        :param _data:
        :return:
        """
        for product_name, filter_method in filter_map.items():
            if product_name in _self_params.rule['name'].lower():
                return filter_method(_self_params, _data)

    def logic(_self_params, _data: list):
        """
        Логика
        :param _self_params:
        :param _data:
        :return:
        """
        correlation_rule_name = _self_params.rule['name']
        # Сначала выполняется обработчики по продуктам
        for product_name, logic_method in logic_map.items():
            if product_name in correlation_rule_name.lower():
                _data, correlation_rule_name = logic_method(_self_params, _data, correlation_rule_name)
                continue

        # общая логика обработки для всех, независимо от продукта
        alert = common_logic(_self_params, _data, correlation_rule_name)

        return alert

    # Если найдено только одно событие, оно прилетает словарём, упаковываем в список
    if isinstance(data, dict):
        data = [data]

    # фильтрация
    data = filtering(self_params, data)
    if not data:  # Если после фильтрации не осталось данных, прекращаем обработку
        return None

    # логика
    alert = logic(self_params, data)
    return alert
