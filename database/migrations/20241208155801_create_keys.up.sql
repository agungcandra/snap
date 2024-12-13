BEGIN;

CREATE TABLE keys (
    id BIGSERIAL PRIMARY KEY,
    client_id UUID NOT NULL REFERENCES clients(id),
    encrypted_key BYTEA NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMIT;