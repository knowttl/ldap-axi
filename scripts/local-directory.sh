#!/usr/bin/env bash
# Runs the opt-in local-directory suite (docs/design/v1.md §18.4) against an ephemeral Samba AD
# domain controller, then OpenLDAP plus MIT KDC. Linux and Docker only; each mock and its
# throwaway credentials exist only for the duration of its runner.
#
#   npm run build && npm run test:local-directory
#
set -euo pipefail

suffix=$(node -e 'process.stdout.write(require("node:crypto").randomUUID())')
network=ldap-axi-test-$suffix-net
dc_container=ldap-axi-test-$suffix-dc
client_container=ldap-axi-test-$suffix-client
dc_host=dc.ldap.test
realm=LDAP.TEST
workgroup=LDAPTEST
base="DC=ldap,DC=test"
# Synthetic credential for a domain that is destroyed when this script exits. No real directory
# credential may ever reach this repository or any automated service (docs/design/v1.md §11).
administrator_password='Passw0rd-local-directory'
dc_image=ubuntu@sha256:b3cc40b72b93588182b5410f723c7aaf142363311c2aa993d8a453ddcbb3ae15
client_image=node@sha256:6dac556d980b7f0e5498d08f08cee0ca67798b4ad6c23964a9214920e67758d0

test -f dist/src/cli.js || { echo "run npm run build first: dist/src/cli.js is missing" >&2; exit 1; }
test -d node_modules/ldapts || { echo "run npm ci first: node_modules is missing" >&2; exit 1; }

cleanup() {
  docker rm --force "$client_container" "$dc_container" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create "$network" >/dev/null
docker run --detach --name "$dc_container" --network "$network" --network-alias "$dc_host" --hostname dc "$dc_image" sleep infinity >/dev/null
docker exec --env DEBIAN_FRONTEND=noninteractive "$dc_container" bash -c 'apt-get update -qq && apt-get install -y -qq samba winbind' >/dev/null

# posix:eadb keeps the sysvol ACLs in a tdb: the container filesystem has no user xattrs, and the
# provision aborts with NT_STATUS_ACCESS_DENIED without it.
docker exec "$dc_container" bash -c "rm -f /etc/samba/smb.conf && samba-tool domain provision \
  --use-rfc2307 --realm=$realm --domain=$workgroup --server-role=dc --host-name=dc \
  --adminpass='$administrator_password' --option='posix:eadb=/var/lib/samba/eadb.tdb'" >/dev/null
docker exec --detach "$dc_container" samba --interactive --debuglevel=1

for attempt in $(seq 1 60); do
  if docker exec "$dc_container" bash -c 'exec 3<>/dev/tcp/127.0.0.1/636' 2>/dev/null; then break; fi
  test "$attempt" -lt 60 || { echo "the Samba AD DC did not start listening on LDAPS" >&2; exit 1; }
  sleep 2
done

docker run --detach --name "$client_container" --network "$network" --volume "$PWD:/work:ro" --workdir /work \
  --env HOME=/tmp/ldap-axi-home --env XDG_CONFIG_HOME=/tmp/ldap-axi-config \
  --env XDG_CACHE_HOME=/tmp/ldap-axi-cache --env XDG_DATA_HOME=/tmp/ldap-axi-data --env XDG_STATE_HOME=/tmp/ldap-axi-state \
  --env KRB5_CONFIG=/tmp/ldap-axi-krb5.conf --env KRB5CCNAME=FILE:/tmp/ldap-axi-ccache \
  --env KRB5_KTNAME=/tmp/absent.keytab --env KRB5_CLIENT_KTNAME=/tmp/absent-client.keytab \
  "$client_image" sleep infinity >/dev/null
docker exec --env DEBIAN_FRONTEND=noninteractive "$client_container" bash -c 'apt-get update -qq && apt-get install -y -qq krb5-user' >/dev/null

# rdns=false is load-bearing: MIT krb5 otherwise canonicalizes the host-based service through the
# container's PTR name and the GSSAPI context fails with "Server not found in Kerberos database".
docker exec --interactive "$client_container" bash -c 'mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME"; cat > "$KRB5_CONFIG"' <<EOF
[libdefaults]
  default_realm = $realm
  rdns = false
  dns_lookup_realm = false
  dns_lookup_kdc = false

[realms]
  $realm = {
    kdc = $dc_host
  }

[domain_realm]
  .ldap.test = $realm
  ldap.test = $realm
EOF
docker exec "$dc_container" cat /var/lib/samba/private/tls/ca.pem | docker exec --interactive "$client_container" bash -c 'cat > /tmp/ca.pem'
docker exec --interactive "$client_container" bash -c "kinit Administrator@$realm >/dev/null" <<<"$administrator_password"

docker exec \
  --env LDAP_AXI_LOCAL_DIRECTORY=1 \
  --env "LDAP_AXI_URL=ldaps://$dc_host:636" \
  --env "LDAP_AXI_LOCAL_DIRECTORY_CA=/tmp/ca.pem" \
  --env "LDAP_AXI_LOCAL_DIRECTORY_BASE=$base" \
  --env "LDAP_AXI_BIND_DN=CN=Administrator,CN=Users,$base" \
  --env "LDAP_AXI_BIND_PASSWORD=$administrator_password" \
  "$client_container" node --test dist/test/local-directory/samba-ad.test.js

cleanup
trap - EXIT
node scripts/local-openldap.ts
