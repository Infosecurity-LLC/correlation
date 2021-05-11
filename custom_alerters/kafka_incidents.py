from elastalert.alerts import Alerter
from socutils import kafkaconn
from socutils.exceptions import KafkaSettingsError
import hashlib
import time

class WrongKafkaSettings(Exception):
    pass

class AuthSettingError(Exception):
    pass

class WrongAlertBody(Exception):
    pass

class KafkaAlerter(Alerter):
    """ Creates a Kafka message for each alert """
    required_options = frozenset(['kafka_auth_type', 'kafka_auth_params', 'kafka_servers', 'kafka_topics', 'name'])

    def __init__(self, rule):
        super(KafkaAlerter, self).__init__(rule)
        self.auth_type = self.rule['kafka_auth_type']
        self.auth_params = self.rule['kafka_auth_params']
        self.servers = self.rule['kafka_servers']
        self.topics = self.rule['kafka_topics']
        self.rule_name = self.rule['name']
        self.producer = self.prepare_producer()

    def prepare_producer(self) -> kafkaconn.confluentkafka.Producer:
        try:
            auth = kafkaconn.auth.Auth(auth=self.auth_type, **self.auth_params)
        except AuthSettingError as e:
            raise WrongKafkaSettings(f"Invalid authorization data passed: {str(e)} auth_type={self.auth_type} "
                                     f"auth_params={self.auth_params}")

        try:
            producer = kafkaconn.confluentkafka.Producer(servers=self.servers,
                                                         auth_params=auth.get_params())
        except KafkaSettingsError as e:
            raise WrongKafkaSettings(f"Invalid kafka data passed: {str(e)}, servers={self.servers}")

        producer.create_producer()
        return producer

    def alert(self, matches):
        if not isinstance(matches, dict) and not isinstance(matches, list):
            raise WrongAlertBody(f"Wrong message: {matches}")

        if isinstance(matches, dict):
            matches = [matches]

        def get_incident_id(correlation_list: list, rule_name_in):
            _firstCorrelation = correlation_list[0]
            _organization = _firstCorrelation['collector']['organization']
            _correlationIds = []
            for correlation in correlation_list:
                _correlationIds.extend(correlation['correlation']['eventIds'])
            _correlationIdsStr = ''.join(_correlationIds)
            _incidentId = hashlib.new('ripemd160')
            _incidentId.update((_organization + _correlationIdsStr + rule_name_in).encode('utf-8'))
            _incidentId = _incidentId.hexdigest()
            return _incidentId
        
        # На данный момент по-умолчанию уровень важности инцидента равно 
        # максимальному уровню среди скоррелированных событий.
        def get_severity_level(correlation_list: list):
            # Минимальный уровень важности д/б LOW
            _severityLevelId = 1
            _severityLevel = ""
            importance_level = {
                'INFO': 0,
                'LOW': 1,
                'MEDIUM': 2,
                'HIGH': 3
            }
            for correlation in correlation_list:
                if importance_level[correlation['interaction']['importance']] > _severityLevelId:
                    _severityLevelId = importance_level[correlation['interaction']['importance']]
            for _value, _id in importance_level.items():
                if _id == _severityLevelId:
                    _severityLevel = _value
            return _severityLevel

        def get_ids_corr_events(correlation_list: list, limit: int = 10):
            _eventIdsInCorr = []
            _rawIdsInCorr = []
            _eventCountInCorr = 0
            for correlation in correlation_list:
                for eventid in correlation['correlation']['eventIds']:
                    if len(_eventIdsInCorr) < limit:
                        _eventIdsInCorr.append(eventid)
                for rawid in correlation['data']['rawIds']:
                    if len(_rawIdsInCorr) < limit:
                        _rawIdsInCorr.append(rawid)
                _eventCountInCorr = _eventCountInCorr + correlation['correlation']['count']
            return _eventIdsInCorr, _rawIdsInCorr, _eventCountInCorr
        
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

            _message = clear_normalized_event(_message, del_words)
            return _message

        incident_id = get_incident_id(matches, self.rule_name)
        if 'severity' in self.rule:
            severity_level = self.rule['severity']
        else:
            severity_level = get_severity_level(matches)
        usecase_id = "SOC-" + self.rule_name.split("-")[1]
        event_ids_in_corr, raw_ids_in_corr, event_count_in_corr = get_ids_corr_events(matches, 10)

        keys_for_del = ['num_matches', 'num_hits', '_type', '_index', '_id']
        
        if 'aggregation_key' in self.rule:
            if isinstance(self.rule['aggregation_key'], list):
                aggregation_keys = self.rule['aggregation_key']
            else:
                aggregation_keys = [self.rule['aggregation_key']]
            aggregation_keys_str = ','.join(aggregation_keys)
            keys_for_del.append(aggregation_keys_str)

        if 'query_key' in self.rule:
            if isinstance(self.rule['query_key'], list):
                query_keys = self.rule['query_key']
            else:
                query_keys = [self.rule['query_key']]
            query_keys_str = ','.join(query_keys)
            keys_for_del.append(query_keys_str)
        
        correlation_event = matches[0]
        correlation_event = clear_stuff_items(correlation_event, keys_for_del)
        correlation_event['data']['rawIds'] = raw_ids_in_corr
        correlation_event['correlation']['eventIds'] = event_ids_in_corr
        correlation_event['correlation']['count'] = event_count_in_corr

        body = {'id': incident_id,
                'detectedTime': int(time.time()),
                'correlationRuleName': self.rule_name,
                'usecaseId': usecase_id,
                'severityLevel': severity_level,
                'correlationEvent': correlation_event}

        for topic in self.topics:
            self.producer.send_json(topic, body)

    def get_info(self):
        return {
            'type': 'kafka',
            'kafka_auth_type': self.auth_type,
            'kafka_auth_params': self.auth_params,
            'kafka_servers': self.servers,
            'kafka_topics': self.topics
        }
