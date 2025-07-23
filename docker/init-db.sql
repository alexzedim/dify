-- Create the Keycloak database if it doesn't exist
SELECT 'CREATE DATABASE keycloak'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'keycloak')\gexec

-- Create the plugin database if it doesn't exist
SELECT 'CREATE DATABASE dify_plugin'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'dify_plugin')\gexec
