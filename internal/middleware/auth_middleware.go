package middleware

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/username/lms-auth-service/internal/models"
	"github.com/username/lms-auth-service/internal/services"
)

// ContextKeyUser is the key used to store decoded JWT claims inside echo.Context.
const ContextKeyUser = "user_claims"

type AuthMiddleware struct{
	tokenService *services.TokenService 
}

func NewAuthMiddleware(tokenService *services.TokenService) *AuthMiddleware {
	return &AuthMiddleware{
		tokenService: tokenService,
	}
}

// Authenticate verifies the Bearer token and attaches the user claims to the request context.
func (m *AuthMiddleware) Authenticate(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authrization")
		if authHeader == "" {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "missing authorization header",
			})
		}

		// Expecting format: "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer"{
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "invalid authorization header format",
			})
		}

		tokenString := parts[1]

		// Validate token signature, expiration, and Redis blacklist using request context
		claims, err := m.tokenService.ValidateToken(c.Request().Context(), tokenString, models.AccessToken)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "unauthorized: " + err.Error(),
			})
		}

		// Store claims in Echo context so downstream middlewares and handlers can read them
		c.Set(ContextKeyUser, claims)

		// Proceed to the next middleware or handler
		return next(c)
	}

}

// RequireRoles enforces Role-Based Access Control (RBAC).
// It accepts a variadic list of allowed roles (e.g., RoleTeacher, RoleAdmin).
func (m *AuthMiddleware) RequireRoles(allowedRoles ...models.Role) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Retrieve claims set by the Authenticate middleware
			userClaims, ok := c.Get(ContextKeyUser).(*models.JwtCustomClaims)
			if !ok || userClaims == nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "user context not found",
				})
			}

			// Check if the user's role matches any of the allowed roles for this route
			for _, role := range allowedRoles {
				if userClaims.Role == role {
					return next(c) // Role is authorized, proceed!
				}
			}

			// User is authenticated, but lacks permission for this specific resource (403 Forbidden)
			return c.JSON(http.StatusForbidden, map[string]string{
				"error": "forbidden: your role (" + string(userClaims.Role) + ") does not have access to this resource",
			})
		}
	}
}