-- name: InsertNonce :exec
INSERT INTO nonces(key_id, nonce) VALUES (@key_id, @nonce);
