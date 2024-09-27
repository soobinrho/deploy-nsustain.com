#!/usr/bin/env bash

cd /home/soobinrho/deploy-nsustain.com
docker compose exec nginx certbot certonly --webroot -d nsustain.com -d beemovr.nsustain.com -d goodlifefarms.nsustain.com --text --non-interactive --agree-tos --email soobinrho@nsustain.com --webroot-path /var/www/letsencrypt/ --server https://acme-v02.api.letsencrypt.org/directory --rsa-key-size 4096 --verbose --keep-until-expiring --preferred-challenges=http | xargs logger --id --priority cron.info
