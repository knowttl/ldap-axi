#!/bin/sh
set -eu
export KRB5_CONFIG=/opt/mock/krb5.conf KRB5_KTNAME=/data/krb/ldap.keytab
mkdir -p /data/ldap /run/openldap
chown -R ldap:ldap /data/ldap /data/tls /data/rootpw.conf /run/openldap
chmod 640 /data/krb/ldap.keytab
chgrp ldap /data/krb /data/krb/ldap.keytab
chmod 750 /data/krb
exec slapd -u ldap -g ldap -f /opt/mock/slapd.conf -h 'ldap:/// ldaps:///' -d 256
