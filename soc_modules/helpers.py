import json
import datetime

class HelperGetValueError(Exception):
    pass


def getval(self_params, data: dict, path: str, required_field: bool = True):
    """
    Получение данных из словаря по пути ключей
    :param self_params:
    :param data: словарьс данными
    :param path: путь через точку
    :param required_field: обязательный ли путь или значение по нему,
    если поля/значения не существует - отправить сообщение об ошибке и продолжить работу с null
    :return:
    """
    ES = self_params.ESInstance
    rule_name = self_params.rule['name']
    def write_error_info_to_EA_service_index(_ES, _message, _problemField, _problemDoc, _ruleName):
        body = {
            "message": f'{_message}: {_problemField}',
            "traceback": f'{_problemDoc}',
            "data": {"rule": f'{_ruleName}'},
            "@timestamp": f'{datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}'
        }
        _ES.index(index='elastalert_status_error', doc_type='_doc', body=body)

    event = data
    nodes = path.split(".")
    for node in nodes:
        if not isinstance(data, dict):
            return None
        data = data.get(node)
        if not data:
            data = "null"
            if required_field:
                message = 'Required field not exist'
                problem_field = 'Node "%s" in path "%s"' % (node, path)
                problem_event = json.dumps(event)
                write_error_info_to_EA_service_index(ES, message, problem_field, problem_event, rule_name)
    return data
