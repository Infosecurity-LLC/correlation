from datetime import datetime
from soc_modules.helpers import getval


class OSLogic:
    def __init__(self):
        pass

    @staticmethod
    def get_windows_chang_time_corr_rule_name(events: list, _selfParams, corr_rule_name_in) -> str:
        """Генерирует новое имя для правила корреляции, с целью выявления,
        изменилось ли время на узле более чем на 5 минут
        """
        _corrRuleName = ""
        _is_more = False
        for event in events:
            # raw_date_format: '2020-11-02T10:36:06.474026900Z'
            previous_time = datetime.fromisoformat(getval(_selfParams, event, "object.property").split('.')[0])
            new_time = datetime.fromisoformat(getval(_selfParams, event, "object.value").split('.')[0])

            delta = abs((new_time - previous_time).total_seconds())
            if delta > 300:
                _is_more = True

        if _is_more:
            _corrRuleName = corr_rule_name_in + '-OVER-FIVE-MINUTES'
        else:
            _corrRuleName = corr_rule_name_in + '-LESS-FIVE-MINUTES'
        return _corrRuleName


def apply_logic(self_params, data: list, correlation_rule_name):
    """
    Логика обработки событий ОС
    :param self_params:
    :param data:
    :param correlation_rule_name:
    :return:
    """
    osl = OSLogic()

    if correlation_rule_name == 'CORR-MSWINDOWS-CHANGING-SYSTEM-TIME':
        correlation_rule_name = osl.get_windows_chang_time_corr_rule_name(data, self_params, correlation_rule_name)

    return data, correlation_rule_name
