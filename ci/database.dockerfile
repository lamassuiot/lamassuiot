FROM postgres:14.1
COPY ./db/alerts.sql /docker-entrypoint-initdb.d/
COPY ./db/auth.sql /docker-entrypoint-initdb.d/
COPY ./db/ca.sql /docker-entrypoint-initdb.d/
COPY ./db/cloud-proxy.sql /docker-entrypoint-initdb.d/
COPY ./db/device-manager.sql /docker-entrypoint-initdb.d/
COPY ./db/dms-manager.sql /docker-entrypoint-initdb.d/