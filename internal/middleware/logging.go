package middleware

// ANCHOR: Logging Imports Cleanup - Build fix - Feb 25, 2026
// Remove unused fmt import to satisfy the compiler.
import (
	"log"
	"net/http"
	"time"
)

// LoggingMiddleware creates request logging middleware
func LoggingMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			log.Printf("[%s] %s %s", r.Method, r.URL.Path, r.RemoteAddr)

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)
			log.Printf("[%d] %s %s completed in %v", wrapped.statusCode, r.Method, r.URL.Path, duration)
		})
	}
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
