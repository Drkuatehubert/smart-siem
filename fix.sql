UPDATE users SET hashed_password = 'HASH_ICI', failed_login_count = 0, locked_until = NULL WHERE username = 'admin';
