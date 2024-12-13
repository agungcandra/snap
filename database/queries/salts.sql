-- name: InsertSalt :exec
INSERT INTO salts(key_id, salt) VALUES (@key_id, @salt);
