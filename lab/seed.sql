-- Lab database seed. Idempotent: safe to run on every setup.
-- Run by scripts/setup_lab.sh as the postgres superuser over the lab cluster's
-- unix socket, with psql variables db_name and db_user set and the password in
-- the DB_PASSWORD environment variable (read with \getenv, so it never appears
-- in a process list). All people and data below are fictional.

\set ON_ERROR_STOP on
\getenv db_password DB_PASSWORD
SET client_min_messages = warning;

-- Least-privileged application role (SELECT only, granted below).
SELECT format('CREATE ROLE %I LOGIN', :'db_user')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'db_user') \gexec
ALTER ROLE :"db_user" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'db_password';

SELECT format('CREATE DATABASE %I', :'db_name')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db_name') \gexec

\connect :"db_name"
SET client_min_messages = warning;

CREATE TABLE IF NOT EXISTS records (
    id          integer PRIMARY KEY,
    full_name   text    NOT NULL,
    department  text    NOT NULL,
    email       text    NOT NULL,
    salary      integer NOT NULL
);

INSERT INTO records (id, full_name, department, email, salary) VALUES
    ( 1, 'Avery Lindqvist',   'Finance',     'avery.lindqvist@example.com',   78000),
    ( 2, 'Bruno Okafor',      'Engineering', 'bruno.okafor@example.com',      96000),
    ( 3, 'Carmen Reyes',      'Sales',       'carmen.reyes@example.com',      64000),
    ( 4, 'Dmitri Volkov',     'Engineering', 'dmitri.volkov@example.com',     101000),
    ( 5, 'Elena Marchetti',   'HR',          'elena.marchetti@example.com',   59000),
    ( 6, 'Farah Haddad',      'Legal',       'farah.haddad@example.com',      88000),
    ( 7, 'Gustavo Pereira',   'Support',     'gustavo.pereira@example.com',   47000),
    ( 8, 'Hana Kobayashi',    'Engineering', 'hana.kobayashi@example.com',    99000),
    ( 9, 'Ibrahim Diallo',    'Finance',     'ibrahim.diallo@example.com',    73000),
    (10, 'Julia Novak',       'Marketing',   'julia.novak@example.com',       61000),
    (11, 'Kwame Mensah',      'Sales',       'kwame.mensah@example.com',      66000),
    (12, 'Lucia Fernandez',   'Support',     'lucia.fernandez@example.com',   48000),
    (13, 'Mateo Rossi',       'Engineering', 'mateo.rossi@example.com',       94000),
    (14, 'Nadia Petrova',     'Security',    'nadia.petrova@example.com',     105000),
    (15, 'Oskar Nilsson',     'Operations',  'oskar.nilsson@example.com',     69000),
    (16, 'Priya Raman',       'Engineering', 'priya.raman@example.com',       98000),
    (17, 'Quentin Dubois',    'Marketing',   'quentin.dubois@example.com',    60000),
    (18, 'Rosa Alvarez',      'HR',          'rosa.alvarez@example.com',      57000),
    (19, 'Samuel Adeyemi',    'Operations',  'samuel.adeyemi@example.com',    71000),
    (20, 'Tamar Cohen',       'Legal',       'tamar.cohen@example.com',       91000),
    (21, 'Umar Siddiqui',     'Finance',     'umar.siddiqui@example.com',     76000),
    (22, 'Valentina Costa',   'Sales',       'valentina.costa@example.com',   65000),
    (23, 'Wei Zhang',         'Security',    'wei.zhang@example.com',         103000),
    (24, 'Ximena Torres',     'Support',     'ximena.torres@example.com',     49000),
    (25, 'Yusuf Demir',       'Operations',  'yusuf.demir@example.com',       70000)
ON CONFLICT (id) DO UPDATE SET
    full_name  = EXCLUDED.full_name,
    department = EXCLUDED.department,
    email      = EXCLUDED.email,
    salary     = EXCLUDED.salary;

-- SELECT only: no writes, no other tables.
REVOKE ALL ON DATABASE :"db_name" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db_name" TO :"db_user";
GRANT USAGE ON SCHEMA public TO :"db_user";
REVOKE ALL ON records FROM :"db_user";
GRANT SELECT ON records TO :"db_user";
