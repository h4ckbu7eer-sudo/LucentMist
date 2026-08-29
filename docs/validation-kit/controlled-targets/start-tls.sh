#!/bin/sh
set -eu

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -keyout /validation/key.pem \
  -out /validation/cert.pem \
  -days 7 \
  -subj '/CN=validation-tls.local' \
  -addext 'subjectAltName=DNS:validation-tls.local,IP:172.30.0.11'

rm -f /etc/nginx/sites-enabled/default
cp /validation/tls.conf /etc/nginx/conf.d/default.conf
exec nginx -g 'daemon off;'

