# Database honeypot: MariaDB with synthetic TransNova data baked in.
FROM mariadb:11.4.9

# Ownership is set here so the named log volume starts writable by mysql (uid 999) and
# readable by the sensor, which runs as the same uid.
RUN mkdir -p /opt/honeypot /var/log/mysql /var/lib/mysql-no-file-io \
 && chown -R mysql:mysql /var/log/mysql \
 && chmod 750 /var/log/mysql \
 && chmod 555 /var/lib/mysql-no-file-io

COPY conf/honeypot.cnf /etc/mysql/conf.d/honeypot.cnf
COPY initdb/accounts.sql.tmpl /opt/honeypot/accounts.sql.tmpl
COPY initdb/01_schema.sql initdb/02_seed.sql initdb/03_accounts.sh /docker-entrypoint-initdb.d/
