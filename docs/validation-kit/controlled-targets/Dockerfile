FROM ubuntu:22.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        nginx \
        openssh-server \
        openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /validation \
    && ssh-keygen -A

COPY sshd-validation.conf /etc/ssh/sshd_config.d/validation.conf
COPY http.conf tls.conf /validation/
COPY start-http.sh start-tls.sh /usr/local/bin/

RUN chmod 0755 /usr/local/bin/start-http.sh /usr/local/bin/start-tls.sh

