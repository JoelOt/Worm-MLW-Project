# Use an older Ubuntu image known to contain the vulnerable Bash 4.3
FROM ubuntu:14.04

# Maintainer label (optional but good practice)
LABEL maintainer="Vulnerable Environment Setup"

# 1. Install Apache Web Server and build dependencies
# We use 'apache2' instead of 'apache2-mpm-worker' as it's simpler on this older base
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 net-tools build-essential wget bison --no-install-recommends && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 1.5. Compile and Install Vulnerable Bash 4.3
# We download the source, compile it, and replace /bin/bash
RUN wget http://ftp.gnu.org/gnu/bash/bash-4.3.tar.gz && \
    tar zxvf bash-4.3.tar.gz && \
    cd bash-4.3 && \
    ./configure && \
    make && \
    make install && \
    mv /usr/local/bin/bash /bin/bash && \
    cd .. && \
    rm -rf bash-4.3 bash-4.3.tar.gz

RUN ln -s /tmp /var/www/html/rce_test
RUN chown -R www-data:www-data /var/www/html

# 2. Habilitar el módulo CGI (Asegurarse de que esté habilitado)
RUN a2enmod cgi

# 3. Configurar el Directorio CGI: ESTE PASO ES EL CRÍTICO
# Asegura que cualquier archivo con extensión .cgi o .sh en cgi-bin sea ejecutado
RUN echo '<Directory "/usr/lib/cgi-bin">' > /etc/apache2/conf-available/cgi-exec.conf && \
    echo '    Options +ExecCGI' >> /etc/apache2/conf-available/cgi-exec.conf && \
    echo '    AddHandler cgi-script .cgi .sh' >> /etc/apache2/conf-available/cgi-exec.conf && \
    echo '</Directory>' >> /etc/apache2/conf-available/cgi-exec.conf && \
    a2enconf cgi-exec

# 3.5. Arreglar Permisos (Para que el exploit de /tmp funcione si lo necesita)
RUN chown -R www-data:www-data /var/www/html && \
    ln -s /tmp /var/www/html/rce_test

# 3.6. Asegurar FollowSymLinks (Usado anteriormente, mantener para robustez)
RUN sed -i 's/Options Indexes FollowSymLinks/Options Indexes FollowSymLinks MultiViews/' /etc/apache2/apache2.conf

# 4. Create the vulnerable Bash CGI script (status.cgi)
# The output is sent back to the browser.
RUN echo '#!/bin/bash' > /usr/lib/cgi-bin/status.cgi && \
    echo 'echo "Content-type: text/html"' >> /usr/lib/cgi-bin/status.cgi && \
    echo 'echo ""' >> /usr/lib/cgi-bin/status.cgi && \
    echo 'echo "<html><body><h1>System Status Page</h1>"' >> /usr/lib/cgi-bin/status.cgi && \
    echo 'echo "<p>Current Bash Version: $BASH_VERSION</p>"' >> /usr/lib/cgi-bin/status.cgi && \
    echo 'echo "</body></html>"' >> /usr/lib/cgi-bin/status.cgi

# 5. Set executable permissions
RUN chmod 755 /usr/lib/cgi-bin/status.cgi

# 6. Expose the standard HTTP port
EXPOSE 80

# 7. Start the Apache web server in the foreground
CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]