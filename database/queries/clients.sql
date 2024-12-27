-- name: InsertClient :one
INSERT INTO clients(id, name, public_key) VALUES (@id, @name, @public_key) RETURNING *;
