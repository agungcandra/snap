-- name: InsertClient :one
INSERT INTO clients(id, name) VALUES (@id, @name) RETURNING *;
