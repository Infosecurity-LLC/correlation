from soc_modules.helpers import getval


class AVLogic:
    def __init__(self):
        pass

    @staticmethod
    def get_av_object_corr_rule_name(event_list: list, corr_rule_name_in):
        _corrRuleName = ""
        _neutralizingScore = 0
        _action_neutralized_list = ['remove', 'lock', 'clean', 'quarantine']
        for event in event_list:
            if event['interaction']['action'] in _action_neutralized_list:
                _neutralizingScore += 1
            else:
                _neutralizingScore -= 1

        if _neutralizingScore >= 0:
            _corrRuleName = corr_rule_name_in + "-NEUTRALIZED"
        else:
            _corrRuleName = corr_rule_name_in + "-NOTNEUTRALIZED"
        return _corrRuleName


def apply_logic(self_params, data: list, correlation_rule_name):
    """
    Логика обработки событий антивируса
    :param self_params:
    :param data:
    :param correlation_rule_name:
    :return:
    """
    avl = AVLogic()
    if self_params.rule['event_category'] == "malware" \
            and "EPIDEMIC" not in correlation_rule_name.split("-") \
            and "REINFECTION" not in correlation_rule_name.split("-"):
        correlation_rule_name = avl.get_av_object_corr_rule_name(data, correlation_rule_name)
    return data, correlation_rule_name
