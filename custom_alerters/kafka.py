from elastalert.alerts import Alerter
from socutils import kafkaconn
from socutils.exceptions import KafkaSettingsError


class WrongKafkaSettings(Exception):
    pass


class AuthSettingError(Exception):
    pass


class WrongAlertBody(Exception):
    pass


# TODO возможно, вместо обхода по словарю сделать вручную отправку (то есть вместо send_json)
# TODO потестить с докером


class KafkaAlerter(Alerter):
    """ Creates a Kafka message for each alert """
    required_options = frozenset(['auth_type', 'auth_params', 'servers', 'topics'])

    def __init__(self, rule):
        super(KafkaAlerter, self).__init__(rule)
        self.auth_type = self.rule['auth_type']
        self.auth_params = self.rule['auth_params']
        self.servers = self.rule['servers']
        self.topics = self.rule['topics']
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
        # TODO подабавлять exceptions на разные случай, в частности:
        # TODO если kafka выключена с использованием kill
        for topic in self.topics:
            if isinstance(matches, dict):
                self.producer.send_json(topic, matches)
            if isinstance(matches, list):
                for message in matches:
                    self.producer.send_json(topic, message)

    def get_info(self):
        return {
            'type': 'kafka',
            'auth_type': self.auth_type,
            'auth_params': self.auth_params,
            'servers': self.servers,
            'topics': self.topics
        }
