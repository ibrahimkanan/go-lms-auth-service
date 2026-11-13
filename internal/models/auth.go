package models

import "github.com/golang-jwt/jwt/v5"

// Roles, User structs, and JWT Custom Claims

// Role reprenst a user role in the LMS system
// Using a custom tupe instead type of raw string prevents tupeos across the codebase
type Role string

const (
	RoleStudent Role = "student"
	RoleTeacher Role = "teacher"
	RoleParent Role = "parent"
	RoleAdmin Role = "admin"
)

// TokenType distinguishes between access and refresh tokens so a refresh token
// cannot be used to access protected API endpoints directly.
type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)

// User represents a simplified LMS user model.
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"` // The "-" tag ensures the password is NEVER serialized to JSON
	Role     Role   `json:"role"`
}

// JwtCustomClaims defines the payload stored inside our JWTs.
// It embeds jwt.RegisteredClaims to inherit standard fields like exp, iat, and jti (ID).
type JwtCustomClaims struct {
	UserID    string    `json:"user_id"`
	Role      Role      `json:"role"`
	TokenType TokenType `json:"token_type"`
	jwt.RegisteredClaims
}

// LoginRequest represents the expected JSON body for /login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// RefreshRequest represents the expected JSON body for /refresh.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}