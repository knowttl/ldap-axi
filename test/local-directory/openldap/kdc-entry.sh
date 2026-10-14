#!/bin/sh
set -eu
umask 077
export KRB5_CONFIG=/opt/mock/krb5.conf KRB5_KDC_PROFILE=/opt/mock/kdc.conf
mkdir -p /data/krb /data/secrets /data/tls
# Keep the bytes hashed by slappasswd -T identical to shell-resolved credentials.
openssl rand -hex 24 | tr -d '\n' > /data/secrets/admin.pw
openssl rand -hex 24 | tr -d '\n' > /data/secrets/svc.pw
openssl rand -hex 24 | tr -d '\n' > /data/secrets/alice.pw
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=ldap-axi-test-ca \
  -addext basicConstraints=critical,CA:TRUE -keyout /data/tls/ca.key -out /data/tls/ca.crt 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -subj /CN=localhost \
  -keyout /data/tls/server.key -out /data/tls/server.csr 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > /data/tls/server.ext
openssl x509 -req -days 2 -in /data/tls/server.csr -CA /data/tls/ca.crt -CAkey /data/tls/ca.key \
  -CAcreateserial -extfile /data/tls/server.ext -out /data/tls/server.crt 2>/dev/null
printf 'rootpw %s\n' "$(slappasswd -T /data/secrets/admin.pw)" > /data/rootpw.conf
cp /opt/mock/krb5.conf /data/krb5.conf
: > /data/krb/kadm5.acl
kdb5_util create -s -r LDAPAXI.TEST -P "$(openssl rand -hex 24)" >/dev/null
kadmin.local -q "addprinc -pw $(cat /data/secrets/alice.pw) alice" >/dev/null
kadmin.local -q 'addprinc -randkey ldap/localhost' >/dev/null
kadmin.local -q 'ktadd -k /data/krb/ldap.keytab ldap/localhost' >/dev/null
exec krb5kdc -n
