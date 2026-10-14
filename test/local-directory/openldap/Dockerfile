FROM alpine:3.22
RUN apk add --no-cache openldap openldap-back-mdb openldap-overlay-memberof openldap-overlay-refint \
    openldap-overlay-ppolicy openldap-clients cyrus-sasl cyrus-sasl-gssapiv2 krb5 krb5-server openssl
COPY slapd.conf seed.ldif krb5.conf kdc.conf kdc-entry.sh ldap-entry.sh seed.sh /opt/mock/
