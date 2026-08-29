#!/bin/sh
set -eu

rm -f /etc/nginx/sites-enabled/default
cp /validation/http.conf /etc/nginx/conf.d/default.conf
exec nginx -g 'daemon off;'

