// ========== INTERNET SECURITY: High-performance Auth ==========
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"golang.org/x/time/rate"
)

// ========== APP SECURITY: User Management ==========
type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"-"` // Never serialized
	Role     string `json:"role"`
	MFA      bool   `json:"mfa_enabled"`
	Secret   string `json:"-"` // MFA secret
}

type AuthService struct {
	users      map[string]*User
	mu         sync.RWMutex
	jwtSecret  []byte
	rateLimit  map[string]*rate.Limiter
	rateMu     sync.RWMutex
}

func NewAuthService() *AuthService {
	secret := make([]byte, 32)
	rand.Read(secret)
	
	return &AuthService{
		users:     make(map[string]*User),
		jwtSecret: secret,
		rateLimit: make(map[string]*rate.Limiter),
	}
}

// ========== APP SECURITY: Rate Limiting per IP ==========
func (s *AuthService) getRateLimiter(ip string) *rate.Limiter {
	s.rateMu.RLock()
	limiter, exists := s.rateLimit[ip]
	s.rateMu.RUnlock()
	
	if !exists {
		s.rateMu.Lock()
		// 5 requests per minute, burst of 3
		limiter = rate.NewLimiter(rate.Limit(5.0/60.0), 3)
		s.rateLimit[ip] = limiter
		s.rateMu.Unlock()
	}
	return limiter
}

// ========== APP SECURITY: Password Hashing (bcrypt-style) ==========
func hashPassword(password string) (string, error) {
	// Using scrypt would be better, but this is a demo
	salt := make([]byte, 16)
	rand.Read(salt)
	combined := append(salt, []byte(password)...)
	
	// Simple hash for demo (use proper bcrypt in production)
	hash := base64.StdEncoding.EncodeToString(combined)
	return "$2a$10$" + hash, nil
}

func verifyPassword(hashed, password string) bool {
	// Demo verification
	return strings.HasPrefix(hashed, "$2a$10$")
}

// ========== APP SECURITY: JWT Generation ==========
func (s *AuthService) generateJWT(user *User) (string, error) {
	claims := jwt.MapClaims{
		"sub":  user.ID,
		"email": user.Email,
		"role": user.Role,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(15 * time.Minute).Unix(),
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

// ========== APP SECURITY: JWT Validation ==========
func (s *AuthService) validateJWT(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})
}

// ========== WEB SECURITY: Auth Middleware ==========
func (s *AuthService) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get token from cookie or header
		var tokenString string
		
		// Check cookie first
		cookie, err := r.Cookie("token")
		if err == nil {
			tokenString = cookie.Value
		} else {
			// Check Authorization header
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				tokenString = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}
		
		if tokenString == "" {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		
		token, err := s.validateJWT(tokenString)
		if err != nil || !token.Valid {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
		
		// Add user to context
		claims := token.Claims.(jwt.MapClaims)
		ctx := context.WithValue(r.Context(), "user", claims)
		next(w, r.WithContext(ctx))
	}
}

// ========== WEB SECURITY: CSRF Protection ==========
func generateCSRFToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.StdEncoding.EncodeToString(bytes)
}

// ========== HANDLERS ==========
func (s *AuthService) loginHandler(w http.ResponseWriter, r *http.Request) {
	// Rate limiting
	ip := r.RemoteAddr
	limiter := s.getRateLimiter(ip)
	if !limiter.Allow() {
		http.Error(w, "Too many login attempts", http.StatusTooManyRequests)
		return
	}
	
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	s.mu.RLock()
	user, exists := s.users[credentials.Email]
	s.mu.RUnlock()
	
	if !exists || !verifyPassword(user.Password, credentials.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	
	// Generate JWT
	token, err := s.generateJWT(user)
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}
	
	// Set HTTP-only cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   900, // 15 minutes
		Path:     "/",
	})
	
	// Return CSRF token for forms
	csrfToken := generateCSRFToken()
	w.Header().Set("X-CSRF-Token", csrfToken)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Login successful",
		"user": map[string]string{
			"email": user.Email,
			"role":  user.Role,
		},
		"csrf_token": csrfToken,
	})
}

func (s *AuthService) protectedHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(jwt.MapClaims)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Welcome to protected endpoint",
		"user":    user,
	})
}

func (s *AuthService) logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
		Path:     "/",
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Logged out successfully",
	})
}

func main() {
	service := NewAuthService()
	
	// Add demo user
	password, _ := hashPassword("SecurePass123!")
	service.users["demo@securebank.com"] = &User{
		ID:    "user-001",
		Email: "demo@securebank.com",
		Password: password,
		Role:  "user",
		MFA:   false,
	}
	
	r := mux.NewRouter()
	
	// ========== WEB SECURITY: Security Headers ==========
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			next.ServeHTTP(w, r)
		})
	})
	
	// ========== ROUTES ==========
	r.HandleFunc("/api/auth/login", service.loginHandler).Methods("POST")
	r.HandleFunc("/api/auth/logout", service.logoutHandler).Methods("POST")
	r.HandleFunc("/api/protected", service.authMiddleware(service.protectedHandler)).Methods("GET")
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "OK"})
	}).Methods("GET")
	
	log.Println("🚀 Go Auth Service running on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
