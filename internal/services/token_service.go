package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/username/lms-auth-service/internal/models"
)

// JWT generation, rotation & Redis blacklisting

// TokenService handles JWT creation, validation, and Redis blacklisting
type TokenService struct {
	redisClient   *redis.Client
	accessSecret  []byte
	refreshSecret []byte
}

// NewTokenService initializes the TokenService with its dependencies.
func NewTokenService(redisClient *redis.Client, accessSecret, refreshSecret string) *TokenService {
	return &TokenService{
		redisClient:   redisClient,
		accessSecret:  []byte(accessSecret),
		refreshSecret: []byte(refreshSecret),
	}
}

// GenerateTokenPair creates a new Access Token (15m) and Refresh Token (7d).
func (s *TokenService) GenerateTokenPair(user *models.User) (string, string, error) {
	// 1. Create Access Token (Short-lived: 15 minutes)
	accessToken, err := s.createToken(user, models.AccessToken, 15*time.Minute, s.accessSecret)
	if err != nil {
		return "", "", err
	}

	// 2. Create Refresh Token (Long-lived: 7 days)
	refreshToken, err := s.createToken(user, models.RefreshToken, 7*24*time.Hour, s.refreshSecret)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// createToken is a helper method (private, starts with lowercase) to build and sign a JWT.
func (s *TokenService) createToken(user *models.User, tokenType models.TokenType, ttl time.Duration, secret []byte) (string, error) {
	now := time.Now()
	claims := &models.JwtCustomClaims{
		UserID:    user.ID,
		Role:      user.Role,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(), // Unique JTI for Redis blacklisting
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	// Create token with HS256 signing algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with our secret key
	return token.SignedString(secret)
}

// ValidateToken verifies the cryptographic signature, expiration, token type, and Redis blacklist status.
func (s *TokenService) ValidateToken(ctx context.Context, tokenString string, expectedType models.TokenType) (*models.JwtCustomClaims, error) {
	secret := s.accessSecret
	if expectedType == models.RefreshToken {
		secret = s.refreshSecret
	}

	// ParseWithClaims decodes the token and validates exp/iat automatically
	token, err := jwt.ParseWithClaims(tokenString, &models.JwtCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// SECURITY CHECK: Ensure the signing method is strictly HMAC (HS256)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})

	if err != nil {
		return nil, err
	}

	// Extract custom claims using Go type assertion
	claims, ok := token.Claims.(*models.JwtCustomClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	// Ensure a refresh token isn't being used as an access token (or vice versa)
	if claims.TokenType != expectedType {
		return nil, errors.New("invalid token type for this operation")
	}

	// Check if the token's JTI is blacklisted in Redis
	isBlacklisted, err := s.IsBlacklisted(ctx, claims.ID)
	if err != nil {
		return nil, err
	}
	if isBlacklisted {
		return nil, errors.New("token has been revoked")
	}

	return claims, nil
}

// BlacklistToken stores the token's JTI in Redis for its remaining lifetime (TTL).
func (s *TokenService) BlacklistToken(ctx context.Context, jti string, expiresAt time.Time) error {
	// Calculate how much time is left until the token naturally expires
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// Token is already expired, no need to store it in Redis
		return nil
	}

	key := fmt.Sprintf("blacklist:%s", jti)
	// Store key with value "revoked" and automatic expiration (TTL)
	return s.redisClient.Set(ctx, key, "revoked", ttl).Err()
}

// IsBlacklisted checks if a JTI exists in the Redis blacklist.
func (s *TokenService) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	key := fmt.Sprintf("blacklist:%s", jti)
	val, err := s.redisClient.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return val > 0, nil
}
