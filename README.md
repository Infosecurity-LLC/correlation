# ElastAlert rules library iss SOC 2.0
Тут хранятся наши правила корреляции
## Полезные ссылки и вообще..
* Дока по ElastAlert: https://elastalert.readthedocs.io/en/latest/index.html
* Тулза для просмотра данных в ElasticSearch, что бы не курлить: Kaizen
### CookBook dev
Поднимаем локальный ElasticSearch, docker-compose -f docker-compose.yml up

docker-compose.yml 
```
version: '3.3'

services:
  elasticsearch:
    # v6.8.3
    image: 'bitnami/elasticsearch:6'
    container_name: elasticsearch
    hostname: elasticsearch
    ulimits:
      nofile:
        soft: 65535
        hard: 65535
      memlock:
        soft: -1
        hard: -1
    ports:
      - '9200:9200'
      - '9300:9300'
    networks:
      - local-network
    volumes:
      - elasticsearch_data:/bitnami/elasticsearch/data
    environment:
      - "TZ=Asia/Yekaterinburg"
```

Для проекта correlations создаём вирутальное окружение и ставим туда elastalert как pip-пакет
```
pip install elastalert
```
Создаём служебные индексы для локального ElastAlert:
``` 
elastalert-create-index
```
Правим конфиг elastalert_config.yaml так, что бы он обращался к локальному ElastAlert:
```
es_host: 127.0.0.1
```
Для того, что бы не накидать в индексы ElastAlert'a на тестовом кластере лишнего, в своих правилах указываем локальный адрес ElasticSerch'a:
```
alert: custom_alerters.es.ElasticSearchAlerter
out_es_host: 127.0.0.1
out_es_port: 9200
out_es_index: incident
```
Для запуска ОДНОГО правила используем команду:
```
elastalert --verbose --config elastalert_config.yaml --rule rules/some_test_rule.yaml
``` 
Для запуска всех правил в папке: 
``` 
elastalert --verbose --config elastalert_config.yaml
```    
