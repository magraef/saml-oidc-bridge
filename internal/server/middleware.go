package server

import (
	"net/http"
	"time"

	"go.uber.org/zap"
)

// securityHeadersMiddleware adds security headers to all responses
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// Prevent MIME sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// XSS protection (legacy browsers)
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Content Security Policy
		// Allows inline scripts only for the auto-submit form
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; "+
				"script-src 'unsafe-inline'; "+
				"style-src 'unsafe-inline'; "+
				"form-action 'self' *; "+
				"base-uri 'self'")

		// Strict Transport Security (only if behind HTTPS)
		if s.config.Session.CookieSecure {
			w.Header().Set("Strict-Transport-Security",
				"max-age=31536000; includeSubDomains")
		}

		// Referrer policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions policy - disable unnecessary features
		w.Header().Set("Permissions-Policy",
			"geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=()")

		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs HTTP requests with security-relevant information
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Log request with security context
		s.logger.Debug("HTTP request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("user_agent", r.UserAgent()),
			zap.String("referer", r.Referer()),
		)

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)

		// Log completion with status
		logFunc := s.logger.Debug
		if wrapped.statusCode >= 400 {
			logFunc = s.logger.Warn
		}
		if wrapped.statusCode >= 500 {
			logFunc = s.logger.Error
		}

		logFunc("HTTP request completed",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("status", wrapped.statusCode),
			zap.Duration("duration", duration),
			zap.String("remote_addr", r.RemoteAddr),
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
