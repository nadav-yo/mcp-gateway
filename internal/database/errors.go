package database

import "fmt"

// ErrUserAlreadyExists is returned when attempting to create a user with a username that already exists
type ErrUserAlreadyExists struct {
	Username string
}

func (e ErrUserAlreadyExists) Error() string {
	return fmt.Sprintf("username '%s' already exists", e.Username)
}

// ErrServerAlreadyExists is returned when attempting to create a server with a name that already exists
type ErrServerAlreadyExists struct {
	ServerName string
}

func (e ErrServerAlreadyExists) Error() string {
	return fmt.Sprintf("upstream server with name '%s' already exists", e.ServerName)
}

// ErrUserNotFound is returned when a user is not found
type ErrUserNotFound struct {
	UserID int64
}

func (e ErrUserNotFound) Error() string {
	return fmt.Sprintf("user with ID %d not found", e.UserID)
}

// ErrServerNotFound is returned when a server is not found
type ErrServerNotFound struct {
	ServerID int64
}

func (e ErrServerNotFound) Error() string {
	return fmt.Sprintf("server with ID %d not found", e.ServerID)
}

// ErrInvalidCredentials is returned when user credentials are invalid
type ErrInvalidCredentials struct {
	Username string
}

func (e ErrInvalidCredentials) Error() string {
	return fmt.Sprintf("invalid credentials for user '%s'", e.Username)
}

// ErrTokenNotFound is returned when a token is not found or invalid
type ErrTokenNotFound struct {
	TokenID int64
}

func (e ErrTokenNotFound) Error() string {
	return fmt.Sprintf("token with ID %d not found or invalid", e.TokenID)
}

// ErrTokenExpired is returned when a token has expired
type ErrTokenExpired struct {
	TokenID int64
}

func (e ErrTokenExpired) Error() string {
	return fmt.Sprintf("token with ID %d has expired", e.TokenID)
}

// ErrUserDisabled is returned when trying to authenticate with a disabled user account
type ErrUserDisabled struct {
	Username string
}

func (e ErrUserDisabled) Error() string {
	return fmt.Sprintf("user account '%s' is disabled", e.Username)
}

// ErrTokenDisabled is returned when trying to use a disabled token
type ErrTokenDisabled struct {
	TokenID int64
}

func (e ErrTokenDisabled) Error() string {
	return fmt.Sprintf("token with ID %d is disabled", e.TokenID)
}

// ErrServerNotExists is returned when trying to operate on a non-existent server
type ErrServerNotExists struct {
	ServerID int64
}

func (e ErrServerNotExists) Error() string {
	return fmt.Sprintf("upstream server with ID %d does not exist", e.ServerID)
}

// ErrUserNotExists is returned when trying to operate on a non-existent user
type ErrUserNotExists struct {
	UserID int64
}

func (e ErrUserNotExists) Error() string {
	return fmt.Sprintf("user with ID %d does not exist", e.UserID)
}

// ErrTokenNotExists is returned when trying to operate on a non-existent token
type ErrTokenNotExists struct {
	TokenID int64
}

func (e ErrTokenNotExists) Error() string {
	return fmt.Sprintf("token with ID %d does not exist", e.TokenID)
}
