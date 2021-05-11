from elastalert.util import elastalert_logger
from custom_alerters import SOCAlerter
from elastalert import Elasticsearch


class ElasticSearchOffline(Exception):
    pass


class ElasticSearchSendError(Exception):
    pass


class WrongAlertBody(Exception):
    pass


class ElasticSearchAlerter(SOCAlerter):
    """ Push a message to ElasticSearch index """
    required_options = frozenset([
        'out_es_host',
        'out_es_port',
        'out_es_index',
        'vendor',
        'system',
        'event_category'
    ])

    def __init__(self, rule):
        super(ElasticSearchAlerter, self).__init__(rule)
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
        if not isinstance(matches, dict) and not isinstance(matches, list):
            raise WrongAlertBody(f"Wrong message: {matches}")
        try:
            elastalert_logger.info(f'Matches: {len(matches)}  >> {matches}')
            body = self.format_alert(matches)
            if body:
                self.ESInstance.index(index=self.out_es_index, doc_type='salads', body=body)
        except Exception as e:
            raise ElasticSearchSendError(f"Error in indexing data {e}")

    def get_info(self):
        return {
            'type': 'elasticsearch',
            'out_es': f'{self.out_es_host}:{self.out_es_port}',
            'index': self.out_es_index,
        }
