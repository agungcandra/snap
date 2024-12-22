-- name: InsertClientKey :exec
INSERT INTO client_keys (
  name,
  version,
  data,
  nonce
) VALUES (
  @name,
  COALESCE(
    (SELECT MAX(version) + 1 FROM client_keys WHERE name = @name),
    1
  ),
  @data,
  @nonce
);

-- name: FindLatestClientKeyByName :one
SELECT * FROM client_keys
WHERE name = @name
ORDER BY version DESC
LIMIT 1;
