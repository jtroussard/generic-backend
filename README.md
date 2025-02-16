## PIN

- Test Logout Endpoint via cURL
- Test Registration Endpoint via cURL



## Database Setup

### Create Database and Configure App User
```sql
CREATE DATABASE auth_db;

-- Create the user "app" with a password
CREATE ROLE app WITH LOGIN PASSWORD 'password';

-- Grant privileges to the "app" user on the database "auth_db"
GRANT ALL PRIVILEGES ON DATABASE auth_db TO app;

SELECT usename FROM pg_user;

-- Grant full control over the 'public' schema to your user
GRANT ALL ON SCHEMA public TO app;

-- Grant privileges on future tables to prevent similar issues
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO app;

-- Grant privileges on existing tables (if needed)
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app;

-- Grant privileges on sequences (for auto-increment IDs)
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO app;

SELECT grantee, privilege_type 
FROM information_schema.role_table_grants 
WHERE grantee = 'app';

INSERT INTO users (password, username) VALUES ('testpassword', 'testuser');
SELECT * FROM users;
```

### Create and Configure Test User
```sql
-- Make sure the password is encoded with BCrypt
INSERT INTO users (password, username) VALUES ('testpassword', 'testuser');
SELECT * FROM users;

INSERT INTO user_roles (user_id, role) VALUES (1, 'ROLE_USER');
SELECT * FROM user_roles;

-- Verify Key Mapping
SELECT u.id, u.username, ur.role 
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id;
```

### Test Login and Me Endpoints via cURL
```curl
# Login and save the cookie for future requests
curl -X POST http://localhost:8080/auth/public/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpassword"}' \
  -c cookies.txt -v

# Call a protected endpoint with the attached cookie 
curl -X GET http://localhost:8080/auth/private/me \
  -H "Content-Type: application/json" \
  -b cookies.txt -v
```
### Test Logout Endpoint via cURL
### Test Registration Endpoint via cURL
