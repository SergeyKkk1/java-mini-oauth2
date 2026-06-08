-- Demo credentials (see README.md):
--   user   alice / password         -> role PAYMENTS_ADMIN  (payments:read, payments:write)
--   user   bob   / password         -> role PAYMENTS_READER (payments:read)
--   client payments-service / secret -> scopes from oauth.client-scopes config

DELETE FROM user_roles;
DELETE FROM role_permissions;
DELETE FROM refresh_tokens;
DELETE FROM users;
DELETE FROM roles;
DELETE FROM permissions;
DELETE FROM clients;

INSERT INTO permissions (id, name) VALUES
    (1, 'payments:read'),
    (2, 'payments:write');

INSERT INTO roles (id, name) VALUES
    (1, 'PAYMENTS_READER'),
    (2, 'PAYMENTS_ADMIN');

INSERT INTO role_permissions (role_id, permission_id) VALUES
    (1, 1),   -- PAYMENTS_READER -> payments:read
    (2, 1),   -- PAYMENTS_ADMIN  -> payments:read
    (2, 2);   -- PAYMENTS_ADMIN  -> payments:write

-- Both demo users have the password "password" (same BCrypt hash is fine for a demo).
INSERT INTO users (id, username, password_hash, info) VALUES
    (1, 'alice', '$2a$10$.0wviXh9W97TAikriFYR1efmY.QeSRcvM92MEpogcM1mk9flrmNjq', 'Alice - payments admin'),
    (2, 'bob',   '$2a$10$.0wviXh9W97TAikriFYR1efmY.QeSRcvM92MEpogcM1mk9flrmNjq', 'Bob - payments reader');

INSERT INTO user_roles (user_id, role_id) VALUES
    (1, 2),   -- alice -> PAYMENTS_ADMIN
    (2, 1);   -- bob   -> PAYMENTS_READER

-- Client secret is "secret".
INSERT INTO clients (id, client_secret_hash, info) VALUES
    ('payments-service', '$2a$10$5E7IFqGEbJ08Wclo3vwcQuDAxPH6XlsiFQRtSkMjGpcH4wjOz6skq', 'Demo confidential client');

-- Advance identity sequences past the seeded rows so application/test inserts never collide.
ALTER TABLE users ALTER COLUMN id RESTART WITH 100;
ALTER TABLE roles ALTER COLUMN id RESTART WITH 100;
ALTER TABLE permissions ALTER COLUMN id RESTART WITH 100;
