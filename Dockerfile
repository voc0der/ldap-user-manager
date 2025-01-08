FROM php:8-apache

# Install required packages as root
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libldb-dev libldap2-dev libldap-common \
        libfreetype6-dev \
        libjpeg-dev \
        libpng-dev \
        gosu && \
    rm -rf /var/lib/apt/lists/*

# Configure and install PHP extensions
RUN docker-php-ext-configure gd --with-freetype && \
    docker-php-ext-install -j$(nproc) gd && \
    libdir=$(find /usr -name "libldap.so*" | sed -e 's#/usr/##' -e 's#/libldap.so##') && \
    docker-php-ext-configure ldap --with-libdir=$libdir && \
    docker-php-ext-install -j$(nproc) ldap

# Add PHPMailer archive and extract
ADD https://github.com/PHPMailer/PHPMailer/archive/refs/tags/v6.3.0.tar.gz /tmp
RUN tar -xzf /tmp/v6.3.0.tar.gz -C /opt && mv /opt/PHPMailer-6.3.0 /opt/PHPMailer

# Enable Apache modules
RUN a2enmod rewrite ssl && a2dissite 000-default default-ssl

# Pre-bake Apache configuration
ARG LDAP_SERVER_NAME=localhost
RUN echo "ServerName ${LDAP_SERVER_NAME}" >> /etc/apache2/apache2.conf && \
    echo "<VirtualHost *:80>\n \
    ServerName ${LDAP_SERVER_NAME}\n \
    Redirect permanent / https://${LDAP_SERVER_NAME}/\n \
  </VirtualHost>" > /etc/apache2/sites-enabled/redirect.conf && \
    echo "<VirtualHost *:443>\n \
    ServerName ${LDAP_SERVER_NAME}\n \
    DocumentRoot /opt/ldap_user_manager\n \
    <Directory /opt/ldap_user_manager>\n \
      Require all granted\n \
    </Directory>\n \
    SSLEngine On\n \
    SSLCertificateFile /opt/ssl/${SERVER_CERT_FILENAME}\n \
    SSLCertificateKeyFile /opt/ssl/${SERVER_KEY_FILENAME}\n \
  </VirtualHost>" > /etc/apache2/sites-enabled/lum.conf

# Expose ports
EXPOSE 80
EXPOSE 443

# Copy application files
COPY www/ /opt/ldap_user_manager

# Add and set permissions for the entrypoint script
COPY entrypoint /usr/local/bin/entrypoint
RUN chmod a+x /usr/local/bin/entrypoint

# Set up /etc/ldap/ldap.conf during build to avoid runtime changes
RUN mkdir -p /etc/ldap && \
    echo "TLS_CACERT /opt/ssl/${LDAP_TLS_CACERT}" > /etc/ldap/ldap.conf

# Set up user and group with PUID and PGID
ARG PUID=1000
ARG PGID=1000
RUN groupadd -g ${PGID} appgroup && \
    useradd -u ${PUID} -g appgroup -m appuser && \
    mkdir -p /home/appuser && \
    chown -R appuser:appgroup /home/appuser /opt/ldap_user_manager

# Switch to the non-root user
USER appuser

# Set the entrypoint and command
ENTRYPOINT ["/usr/local/bin/entrypoint"]
CMD ["apache2-foreground"]
