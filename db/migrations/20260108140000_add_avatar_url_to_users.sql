-- migrate:up
ALTER TABLE users ADD COLUMN avatar_url VARCHAR(1024);

-- migrate:down
ALTER TABLE users DROP COLUMN avatar_url;
