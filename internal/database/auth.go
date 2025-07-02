package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/nadav-yo/mcp-gateway/internal/logger"
)

// UserRecord represents a user record in the database
type UserRecord struct {
	ID        int64     `json:"id" db:"id"`
	Username  string    `json:"username" db:"username"`
	Password  string    `json:"-" db:"password_hash"` // Hashed password, not returned in JSON
	IsActive  bool      `json:"is_active" db:"is_active"`
	IsAdmin   bool      `json:"is_admin" db:"is_admin"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// TokenRecord represents an access token record in the database
type TokenRecord struct {
	ID          int64      `json:"id" db:"id"`
	Token       string     `json:"token" db:"token"`
	UserID      int64      `json:"user_id" db:"user_id"`
	Username    string     `json:"username" db:"username"`
	Description string     `json:"description" db:"description"`
	ExpiresAt   *time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	LastUsed    *time.Time `json:"last_used" db:"last_used"`
	IsActive    bool       `json:"is_active" db:"is_active"`
	IsInternal  bool       `json:"is_internal" db:"is_internal"`
}

// CreateUser creates a new user with hashed password
func (db *DB) CreateUser(username, password string) (*UserRecord, error) {
	return db.CreateUserWithAdmin(username, password, false)
}

// CreateUserWithAdmin creates a new user with hashed password and admin flag
func (db *DB) CreateUserWithAdmin(username, password string, isAdmin bool) (*UserRecord, error) {
	// Check if username already exists
	exists, err := db.usernameExists(username)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrUserAlreadyExists{Username: username}
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	query := `
	INSERT INTO users (username, password_hash, is_admin)
	VALUES (?, ?, ?)
	`

	result, err := db.conn.Exec(query, username, string(hashedPassword), isAdmin)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert id: %w", err)
	}

	return db.GetUser(id)
}

// GetUser retrieves a user by ID
func (db *DB) GetUser(id int64) (*UserRecord, error) {
	query := `
	SELECT id, username, password_hash, is_active, is_admin, created_at, updated_at
	FROM users WHERE id = ?
	`

	row := db.conn.QueryRow(query, id)

	var user UserRecord
	err := row.Scan(&user.ID, &user.Username, &user.Password, &user.IsActive, &user.IsAdmin, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound{UserID: id}
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetUserByUsername retrieves a user by username
func (db *DB) GetUserByUsername(username string) (*UserRecord, error) {
	query := `
	SELECT id, username, password_hash, is_active, is_admin, created_at, updated_at
	FROM users WHERE username = ?
	`

	row := db.conn.QueryRow(query, username)

	var user UserRecord
	err := row.Scan(&user.ID, &user.Username, &user.Password, &user.IsActive, &user.IsAdmin, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrInvalidCredentials{Username: username}
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// ListUsers retrieves all users
func (db *DB) ListUsers() ([]*UserRecord, error) {
	query := `
	SELECT id, username, password_hash, is_active, is_admin, created_at, updated_at
	FROM users ORDER BY username
	`

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*UserRecord
	for rows.Next() {
		var user UserRecord
		err := rows.Scan(&user.ID, &user.Username, &user.Password, &user.IsActive, &user.IsAdmin, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, &user)
	}

	return users, nil
}

// UpdateUser updates an existing user
func (db *DB) UpdateUser(id int64, username, password string, isActive, isAdmin bool) (*UserRecord, error) {
	// Check if username already exists (excluding current user)
	exists, err := db.usernameExistsExcludingID(username, id)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrUserAlreadyExists{Username: username}
	}

	var hashedPassword string
	if password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		hashedPassword = string(hash)
	}

	query := `
	UPDATE users SET username = ?, is_active = ?, is_admin = ?, updated_at = CURRENT_TIMESTAMP
	`
	args := []interface{}{username, isActive, isAdmin}

	if hashedPassword != "" {
		query += ", password_hash = ?"
		args = append(args, hashedPassword)
	}

	query += " WHERE id = ?"
	args = append(args, id)

	_, err = db.conn.Exec(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return db.GetUser(id)
}

// DeleteUser deletes a user and all associated tokens
func (db *DB) DeleteUser(id int64) error {
	// First check if user exists
	var exists bool
	err := db.conn.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE id = ?)", id).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check if user exists: %w", err)
	}

	if !exists {
		return ErrUserNotFound{UserID: id}
	}

	// Delete user (tokens will be deleted automatically due to foreign key constraint)
	query := `DELETE FROM users WHERE id = ?`
	_, err = db.conn.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// GetToken retrieves and validates a token
func (db *DB) GetToken(tokenValue string) (*TokenRecord, error) {
	var token TokenRecord

	err := db.retryOnBusy(func() error {
		query := `
		SELECT id, token, user_id, username, description, expires_at, created_at, last_used, is_active, is_internal
		FROM tokens WHERE token = ?
		`

		row := db.conn.QueryRow(query, tokenValue)
		return row.Scan(&token.ID, &token.Token, &token.UserID, &token.Username, &token.Description,
			&token.ExpiresAt, &token.CreatedAt, &token.LastUsed, &token.IsActive, &token.IsInternal)
	}, 5)

	if err != nil {
		return nil, ErrTokenNotFound{TokenID: 0} // We don't have the ID for this case
	}

	return &token, nil
}

// UpdateToken updates token properties
func (db *DB) UpdateToken(tokenValue string, isActive bool) error {
	query := `
	UPDATE tokens SET is_active = ?
	WHERE token = ?
	`

	_, err := db.conn.Exec(query, isActive, tokenValue)
	if err != nil {
		return fmt.Errorf("failed to update token: %w", err)
	}

	return nil
}

// DeleteToken deletes a token
func (db *DB) DeleteToken(tokenValue string) error {
	// First check if token exists
	var exists bool
	err := db.conn.QueryRow("SELECT EXISTS(SELECT 1 FROM tokens WHERE token = ?)", tokenValue).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check if token exists: %w", err)
	}

	if !exists {
		return ErrTokenNotFound{TokenID: 0} // We don't have the ID for this case
	}

	query := `DELETE FROM tokens WHERE token = ?`
	_, err = db.conn.Exec(query, tokenValue)
	if err != nil {
		return fmt.Errorf("failed to delete token: %w", err)
	}

	return nil
}

// initializeDefaultUser creates a default admin user if no users exist
func (db *DB) initializeDefaultUser() error {
	var count int
	err := db.retryOnBusy(func() error {
		return db.conn.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	}, 3)
	if err != nil {
		return fmt.Errorf("failed to count users: %w", err)
	}

	if count > 0 {
		return nil // Users already exist
	}

	// Generate a random password for the admin user
	password := make([]byte, 16)
	if _, err := rand.Read(password); err != nil {
		return fmt.Errorf("failed to generate random password: %w", err)
	}
	passwordStr := hex.EncodeToString(password)

	// Create the admin user
	user, err := db.CreateUserWithAdmin("admin", passwordStr, true)
	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	db_logger := logger.GetLoggerWithContext(map[string]interface{}{
		"username": user.Username,
		"password": passwordStr,
		"message":  "Please change this password after first login",
	})
	db_logger.Info().Msg("Created default admin user")

	return nil
}

// ValidateUser validates username and password
func (db *DB) ValidateUser(username, password string) (*UserRecord, error) {
	user, err := db.GetUserByUsername(username)
	if err != nil {
		return nil, ErrInvalidCredentials{Username: username}
	}

	if !user.IsActive {
		return nil, ErrUserDisabled{Username: username}
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, ErrInvalidCredentials{Username: username}
	}

	return user, nil
}

// CreateToken creates a new access token for a user
func (db *DB) CreateToken(userID int64, username, description string, expiresAt *time.Time, isInternal bool) (*TokenRecord, error) {
	// Generate a random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	err := db.retryOnBusy(func() error {
		query := `
		INSERT INTO tokens (token, user_id, username, description, expires_at, is_internal)
		VALUES (?, ?, ?, ?, ?, ?)
		`

		_, err := db.conn.Exec(query, token, userID, username, description, expiresAt, isInternal)
		return err
	}, 5)

	if err != nil {
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	return db.GetToken(token)
}

// ValidateToken validates a token and updates last_used timestamp asynchronously
func (db *DB) ValidateToken(token string) (*TokenRecord, error) {
	tokenRecord, err := db.GetToken(token)
	if err != nil {
		return nil, err
	}

	if !tokenRecord.IsActive {
		return nil, ErrTokenDisabled{TokenID: tokenRecord.ID}
	}

	// Check if token is expired
	if tokenRecord.ExpiresAt != nil && time.Now().After(*tokenRecord.ExpiresAt) {
		return nil, ErrTokenExpired{TokenID: tokenRecord.ID}
	}

	// Update last_used timestamp asynchronously to avoid blocking validation
	// Only update if more than 1 minute has passed since last update to reduce writes
	if tokenRecord.LastUsed == nil || time.Since(*tokenRecord.LastUsed) > time.Minute {
		go func() {
			// Use a separate goroutine with retry logic for last_used updates
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := db.retryOnBusy(func() error {
				query := `UPDATE tokens SET last_used = CURRENT_TIMESTAMP WHERE token = ?`
				_, err := db.conn.ExecContext(ctx, query, token)
				return err
			}, 3)

			if err != nil {
				db_logger := logger.GetLoggerWithContext(map[string]interface{}{
					"error": err,
					"token": token[:8] + "...",
				})
				db_logger.Error().Err(err).Msg("Failed to update token last_used timestamp after retries")
			}
		}()
	}

	return tokenRecord, nil
}

// ListTokens lists all active and public tokens for a user
func (db *DB) ListTokens(userID int64) ([]TokenRecord, error) {
	query := `
	SELECT id, token, user_id, username, description, expires_at, created_at, last_used, is_active, is_internal
	FROM tokens WHERE user_id = ? AND is_active = true AND is_internal = false ORDER BY created_at DESC
	`

	rows, err := db.conn.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens: %w", err)
	}
	defer rows.Close()

	var tokens []TokenRecord
	for rows.Next() {
		var token TokenRecord
		err := rows.Scan(&token.ID, &token.Token, &token.UserID, &token.Username, &token.Description,
			&token.ExpiresAt, &token.CreatedAt, &token.LastUsed, &token.IsActive, &token.IsInternal)
		if err != nil {
			return nil, fmt.Errorf("failed to scan token: %w", err)
		}
		tokens = append(tokens, token)
	}

	return tokens, nil
}

// RevokeToken revokes (deletes) a token belonging to a user
func (db *DB) RevokeToken(tokenID int64, userID int64) error {
	// First verify that the token belongs to the user
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM tokens WHERE id = ? AND user_id = ?", tokenID, userID).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to verify token ownership: %w", err)
	}

	if count == 0 {
		return ErrTokenNotFound{TokenID: tokenID}
	}

	// Delete the token
	query := `DELETE FROM tokens WHERE id = ? AND user_id = ?`
	result, err := db.conn.Exec(query, tokenID, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrTokenNotFound{TokenID: tokenID}
	}

	return nil
}

// usernameExists checks if a username already exists
func (db *DB) usernameExists(username string) (bool, error) {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)"
	err := db.conn.QueryRow(query, username).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if username exists: %w", err)
	}
	return exists, nil
}

// usernameExistsExcludingID checks if a username exists, excluding a specific user ID
func (db *DB) usernameExistsExcludingID(username string, excludeID int64) (bool, error) {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM users WHERE username = ? AND id != ?)"
	err := db.conn.QueryRow(query, username, excludeID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if username exists: %w", err)
	}
	return exists, nil
}
