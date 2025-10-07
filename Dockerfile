FROM php:8-apache

# ---- OS deps ----
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libldb-dev libldap2-dev libldap-common \
        libfreetype6-dev libjpeg62-turbo-dev libpng-dev \
        dpkg-dev gosu ca-certificates curl; \
    rm -rf /var/lib/apt/lists/*

# ---- PHP extensions ----
# gd: enable freetype + jpeg explicitly
# ldap: use correct multiarch libdir
RUN set -eux; \
    docker-php-ext-configure gd --with-freetype --with-jpeg; \
    docker-php-ext-install -j"$(nproc)" gd; \
    multiarch="$(dpkg-architecture -q DEB_BUILD_MULTIARCH)"; \
    docker-php-ext-configure ldap --with-libdir="lib/${multiarch}"; \
    docker-php-ext-install -j"$(nproc)" ldap

# (openssl is enabled by default in php:8-apache)

# ---- PHPMailer (if you still want it available system-wide) ----
ADD https://github.com/PHPMailer/PHPMailer/archive/refs/tags/v6.3.0.tar.gz /tmp
RUN tar -xzf /tmp/v6.3.0.tar.gz -C /opt && mv /opt/PHPMailer-6.3.0 /opt/PHPMailer

# ---- Apache mods ----
# We'll use mod_headers for extra hardening if desired.
RUN a2enmod rewrite ssl headers && a2dissite 000-default default-ssl

# ---- Apache vhost ----
ENV SERVER_CERT_FILENAME=/ldap-user-manager/cert.crt
ENV SERVER_KEY_FILENAME=/ldap-user-manager/privkey.pem
ARG LDAP_SERVER_NAME=localhost
RUN echo "ServerName ${LDAP_SERVER_NAME}" >> /etc/apache2/apache2.conf && \
    printf "%s\n" "<VirtualHost *:80>
      ServerName ${LDAP_SERVER_NAME}
      Redirect permanent / https://${LDAP_SERVER_NAME}/
    </VirtualHost>" > /etc/apache2/sites-enabled/redirect.conf && \
    printf "%s\n" "<VirtualHost *:443>
      ServerName ${LDAP_SERVER_NAME}
      DocumentRoot /opt/ldap_user_manager
      <Directory /opt/ldap_user_manager>
        AllowOverride All
        Require all granted
        # Optional: strip any spoofed client-sent X-* before your proxy sets them
        # Header unset X-Forwarded-User
        # Header unset Remote-User
        # Header unset Remote-Email
        # Header unset Remote-Groups
      </Directory>
      SSLEngine On
      SSLCertificateFile /opt/ssl/${SERVER_CERT_FILENAME}
      SSLCertificateKeyFile /opt/ssl/${SERVER_KEY_FILENAME}
    </VirtualHost>" > /etc/apache2/sites-enabled/lum.conf

# ---- App files ----
COPY www/ /opt/ldap_user_manager

# ---- Defaults for the mTLS feature ----
# You can override these in docker-compose/environment.
ENV MTLS_DATA_BASE=/opt/ldap_user_manager/data/mtls
ENV MTLS_CERT_BASE=/mnt/mtls-certs
# Only needed if you want expiry parsed from .p12 instead of a PEM:
ENV MTLS_P12_PASS=
ENV MTLS_MAIL_FROM=no-reply@localhost
# Optional Apprise endpoint:
ENV APPRISE_URL=

# ---- Create app user/group and set ownership ----
ARG PUID=1000
ARG PGID=1000
RUN groupadd -g ${PGID} appgroup && \
    useradd -u ${PUID} -g appgroup -m appuser && \
    mkdir -p /home/appuser && \
    chown -R appuser:appgroup /home/appuser /opt/ldap_user_manager

# Create default dirs in the image (nice for local run without bind-mounts)
RUN set -eux; \
    install -d -m 0770 /opt/ldap_user_manager/data/mtls/codes \
                       /opt/ldap_user_manager/data/mtls/tokens \
                       /opt/ldap_user_manager/data/mtls/logs \
                       /mnt/mtls-certs; \
    chown -R appuser:appgroup /opt/ldap_user_manager/data/mtls /mnt/mtls-certs

# ---- Entry point ensures dirs exist even with bind mounts ----
COPY entrypoint /usr/local/bin/entrypoint
RUN chmod a+x /usr/local/bin/entrypoint

# ---- LDAP CA (optional) ----
ARG LDAP_TLS_CACERT=ca.crt
RUN mkdir -p /etc/ldap && \
    echo "TLS_CACERT /opt/ssl/${LDAP_TLS_CACERT}" > /etc/ldap/ldap.conf

# ---- Switch to non-root ----
USER appuser

EXPOSE 80 443
ENTRYPOINT ["/usr/local/bin/entrypoint"]
CMD ["apache2-foreground"]
