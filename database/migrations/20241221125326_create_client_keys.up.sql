BEGIN;

CREATE TABLE client_keys (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    version INT NOT NULL,
    data BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_name_version UNIQUE(name, version)
);

COMMIT;
