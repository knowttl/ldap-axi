#!/bin/sh
set -eu
# Seed through slapd so the memberof overlay maintains real back-links.
sed -e "s|@ALICE@|$(slappasswd -T /data/secrets/alice.pw)|" \
    -e "s|@SVC@|$(slappasswd -T /data/secrets/svc.pw)|" /opt/mock/seed.ldif \
  | ldapadd -x -H ldap://localhost -D cn=admin,dc=ldapaxi,dc=test -y /data/secrets/admin.pw >/dev/null
