-- name: InsertKeyStorage :exec
INSERT INTO key_storages (
  name,
  version,
  data
) VALUES (
  @name,
  COALESCE(
    (SELECT MAX(version) + 1 FROM client_keys WHERE name = @name),
    1
  ),
  @data
);

-- name: FindLatestKeyStorageByName :one
SELECT * FROM key_storages
WHERE name = @name
ORDER BY version DESC
LIMIT 1;
