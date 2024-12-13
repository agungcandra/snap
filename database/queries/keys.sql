-- name: InsertKey :one
INSERT INTO keys(client_id, encrypted_key) VALUES (@client_id, @encrypted_key) RETURNING id;
