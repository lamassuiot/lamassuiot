FROM postgres:14.1
COPY ./db/auth.sql /docker-entrypoint-initdb.d/
COPY ./db/dms-enroller.sql /docker-entrypoint-initdb.d/
COPY ./db/devices.sql /docker-entrypoint-initdb.d/
COPY ./db/cloud-proxy.sql /docker-entrypoint-initdb.d/
COPY ./db/ca.sql /docker-entrypoint-initdb.d/