#!/bin/bash

host=localhost
port=0
dbuser=liquibase

if [ -z ${1+x} ]; then
  echo "Choose run mode for liquibase: updateSql [test mode, prints all sql expressions thal'll be executed against a database] or update [apply changes on database]"
  exit 0;
fi

read -p "DB host: [$host]" tmp
if [ -z ${tmp+x} ]; then : else host=$tmp; fi

read -p "DB port: [$port]" tmp
if [ -z ${tmp+x} ]; then : else port=$tmp; fi

read -p "DB user: [$dbuser]" tmp
if [ -z ${tmp+x} ]; then : else dbuser=$tmp; fi

read -sp 'DB pass: ' dbpass

read -p 'DB name: ' dbname

java -cp liquibase-core-3.6.1.jar:logback-classic-1.2.3.jar:logback-core-1.2.3.jar:postgresql-42.2.5.jar:slf4j-api-1.7.25.jar:snakeyaml-1.25.jar liquibase.integration.commandline.Main --changeLogFile=changelog.yaml --url=jdbc:postgresql://$host:$port/$dbname --username=$dbuser --password=$dbpass $1
