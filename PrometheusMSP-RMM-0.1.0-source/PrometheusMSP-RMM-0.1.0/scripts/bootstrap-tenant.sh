#!/usr/bin/env sh
set -eu

tenant_id=${1:?usage: bootstrap-tenant.sh TENANT_UUID TENANT_NAME}
tenant_name=${2:?usage: bootstrap-tenant.sh TENANT_UUID TENANT_NAME}
case "$tenant_id" in
  ????????-????-????-????-????????????) ;;
  *) echo "TENANT_UUID must be a UUID" >&2; exit 1;;
esac

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
docker compose -f "$root/deploy/docker-compose.yml" exec -T postgres \
  sh -c 'psql -v ON_ERROR_STOP=1 -v tenant_id="$1" -v tenant_name="$2" -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  bootstrap "$tenant_id" "$tenant_name" <<'SQL'
INSERT INTO tenants (id, name)
VALUES (:'tenant_id'::uuid, :'tenant_name')
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name;
SQL
echo "Tenant $tenant_id is ready. Create enrollment tokens through POST /api/v1/enrollment-tokens."
