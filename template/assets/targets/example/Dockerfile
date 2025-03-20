FROM ubuntu:24.04
# Damn Fkin Vulerable Privesc - PHP

# installing all PHP related shenanigans

RUN apt update && apt install -y software-properties-common apache2 curl netcat-traditional openssh-server

RUN add-apt-repository ppa:ondrej/php \
&& apt-get update \
&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tzdata \
&& apt-get install -y php5.6 \
&& apt-get install -y php5.6-mbstring php5.6-mcrypt php5.6-mysql php5.6-xml php5.6-gd php5.6-zip \
&& rm -rf /var/lib/apt/lists/*

# sudo privs

RUN apt update && apt install -y gcc sudo net-tools cron cowsay cpio watch original-awk sqlite3 gdb rc vim
ADD artifacts/sudoers /root/.secret
ADD artifacts/sudoers_wwwdata /etc/sudoers.d/www-data
RUN chmod 0440 /etc/sudoers /etc/sudoers.d/www-data
RUN mkdir -p /usr/local/share/dstat
RUN chown -R www-data:www-data /usr/local/share/dstat

# privesc vuln
RUN ln -s /tmp/dstat /usr/bin/dstat

# cron job
ADD artifacts/php-cleanup /etc/cron.d/php-cleanup

# writable www-data folder => another privesc misdirection
RUN mkdir -p /root/.admintasks
RUN chmod o+x /root
RUN chown -R www-data:www-data /root/.admintasks
RUN chmod 770 /root/.admintasks

# backdoor service => another privesc (based on Linux services)
ADD artifacts/backdoor.service /etc/systemd/system/backdoor.service
#RUN systemctl daemon-reload
RUN systemctl enable backdoor.service

ADD artifacts/services.sh /bin/services.sh
ADD artifacts/000-default.conf /etc/apache2/sites-available/000-default.conf
RUN mkdir -p /var/www/html/upload

# adding of php code
ADD appcode/bricks /var/www/html/bricks
ADD appcode/robots.txt /var/www/html/robots.txt

# changing of perms
RUN chown -R www-data:www-data /var/www/html/
RUN chmod 777 /var/www/html/upload
RUN chmod 777 /var/www/html/bricks/upload-1
RUN chmod 777 /var/www/html/bricks/upload-2
RUN chmod 777 /var/www/html/bricks/upload-3

# for ssh maintenance (defender)
ADD artifacts/sshdconfig /etc/ssh/sshd_config
ADD artifacts/key.pub /root/.ssh/authorized_keys
RUN chmod 400 /root/.ssh/authorized_keys

# for wazuh installation and setup (defender)
WAZUH_INSTALL

CMD ["sh","/bin/services.sh"]

