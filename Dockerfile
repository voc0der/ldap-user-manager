FROM php:8-apache

# Install required packages as root
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libldb-dev libldap2-dev libldap-common \
        libfreetype6-dev \
        libjpeg62-turbo-dev \
        libpng-dev \
        dpkg-dev \
        gosu && \
    rm -rf /var/lib/apt/lists/*

# Configure and install PHP extensions
# - gd: enable freetype + jpeg explicitly
# - ldap: use correct multiarch libdir (fixes "invalid host type: lib/x86_64-linux-gnu.2")
RUN set -eux; \
    docker-php-ext-configure gd --with-freetype --with-jpeg; \
    docker-php-ext-install -j"$(nproc)" gd; \
    multiarch="$(dpkg-architecture -q DEB_BUILD_MULTIARCH)"; \
    docker-php-ext-configure ldap --with-libdir="lib/${multiarch}"; \
    docker-php-ext-install -j"$(nproc)" ldap

# Add PHPMailer archive and extract
ADD https://github.com/PHPMailer/PHPMailer/archive/refs/tags/v6.3.0.tar.gz /tmp
RUN tar -xzf /tmp/v6.3.0.tar.gz -C /opt && mv /opt/PHPMailer-6.3.0 /opt/PHPMailer

# Enable Apache modules
RUN a2enmod rewrite ssl && a2dissite 000-default default-ssl

# Pre-bake Apache configuration
ENV SERVER_CERT_FILENAME=/ldap-user-manager/cert.crt
ENV SERVER_KEY_FILENAME=/ldap-user-manager/privkey.pem
ARG LDAP_SERVER_NAME=localhost
RUN set -eux; \
    echo "ServerName ${LDAP_SERVER_NAME}" >> /etc/apache2/apache2.conf; \
    { \
      echo "<VirtualHost *:80>"; \
      echo "  ServerName ${LDAP_SERVER_NAME}"; \
      echo "  Redirect permanent / https://${LDAP_SERVER_NAME}/"; \
      echo "</VirtualHost>"; \
    } > /etc/apache2/sites-enabled/redirect.conf; \
    { \
      echo "<VirtualHost *:443>"; \
      echo "  ServerName ${LDAP_SERVER_NAME}"; \
      echo "  DocumentRoot /opt/ldap_user_manager"; \
      echo "  <Directory /opt/ldap_user_manager>"; \
      echo "    Require all granted"; \
      echo "  </Directory>"; \
      echo "  SSLEngine On"; \
      echo "  SSLCertificateFile /opt/ssl/${SERVER_CERT_FILENAME}"; \
      echo "  SSLCertificateKeyFile /opt/ssl/${SERVER_KEY_FILENAME}"; \
      echo "</VirtualHost>"; \
    } > /etc/apache2/sites-enabled/lum.conf

# Expose ports
EXPOSE 80
EXPOSE 443

# Copy application files
COPY www/ /opt/ldap_user_manager

# Add and set permissions for the entrypoint script
COPY entrypoint /usr/local/bin/entrypoint
RUN chmod a+x /usr/local/bin/entrypoint

# Set up /etc/ldap/ldap.conf during build to avoid runtime changes
ARG LDAP_TLS_CACERT=ca.crt
RUN mkdir -p /etc/ldap && \
    echo "TLS_CACERT /opt/ssl/${LDAP_TLS_CACERT}" > /etc/ldap/ldap.conf

# >>> CHANGED: remove build-time user/group creation (PUID/PGID handled at runtime by entrypoint)
# (deleted the ARG PUID/PGID + useradd/groupadd + USER appuser block)

# Create mTLS state directories (codes/tokens/logs); ownership fixed at runtime in entrypoint
RUN set -eux; \
    install -d -m 0777 /opt/ldap_user_manager/data/mtls/codes \
                       /opt/ldap_user_manager/data/mtls/tokens \
                       /opt/ldap_user_manager/data/mtls/logs; \
    chmod -R 0777 /opt/ldap_user_manager/data/mtls

# Set the entrypoint and command
ENTRYPOINT ["/usr/local/bin/entrypoint"]
CMD ["apache2-foreground"]
