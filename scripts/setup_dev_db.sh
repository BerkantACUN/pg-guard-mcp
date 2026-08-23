#!/usr/bin/env bash
# Sets up a local pgguard_test database and a genuinely-restricted
# pgguard_readonly role for running the integration test suite.
# Requires a local PostgreSQL superuser connection (adjust -U/-h as needed).
set -euo pipefail

PSQL="${PSQL:-psql}"
SUPERUSER="${PGGUARD_SETUP_SUPERUSER:-postgres}"
HOST="${PGGUARD_SETUP_HOST:-127.0.0.1}"

"$PSQL" -h "$HOST" -U "$SUPERUSER" -v ON_ERROR_STOP=1 <<SQL
DROP DATABASE IF EXISTS pgguard_test;
CREATE DATABASE pgguard_test;
DROP ROLE IF EXISTS pgguard_readonly;
CREATE ROLE pgguard_readonly WITH LOGIN PASSWORD 'pgguard_readonly_dev_pw';
ALTER ROLE pgguard_readonly SET default_transaction_read_only = on;
SQL

"$PSQL" -h "$HOST" -U "$SUPERUSER" -d pgguard_test -v ON_ERROR_STOP=1 <<SQL
CREATE TABLE users (id serial PRIMARY KEY, email text NOT NULL);
INSERT INTO users (email) VALUES ('a@example.com'), ('b@example.com');
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM pgguard_readonly;
REVOKE ALL ON SCHEMA public FROM pgguard_readonly;
GRANT CONNECT ON DATABASE pgguard_test TO pgguard_readonly;
GRANT USAGE ON SCHEMA public TO pgguard_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO pgguard_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO pgguard_readonly;
SQL

echo "pgguard_test database and pgguard_readonly role are ready."
