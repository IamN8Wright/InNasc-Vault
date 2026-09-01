ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0,1));
ALTER TABLE users ADD COLUMN welcome_sent_at TEXT;
ALTER TABLE users ADD COLUMN welcome_send_count INTEGER NOT NULL DEFAULT 0;
