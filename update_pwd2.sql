UPDATE users SET hashed_password = '$2b$12$Q3YzCKkNlh66Nze7POqMyecYVjnvoAS/eCYt2wrC2NTCcIkeZYBBa', failed_login_count = 0, locked_until = NULL WHERE username = 'admin';
