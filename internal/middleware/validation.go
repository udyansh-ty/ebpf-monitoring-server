package middleware

import (
	"encoding/json"
	"net/http"
)

// ValidationMiddleware creates request validation middleware
func ValidationMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Validate Content-Type for POST/PUT requests
			if r.Method == http.MethodPost || r.Method == http.MethodPut {
				contentType := r.Header.Get("Content-Type")
				if contentType != "" && contentType != "application/json" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnsupportedMediaType)
					json.NewEncoder(w).Encode(ErrorResponse{
						Error:   "Unsupported Media Type",
						Code:    http.StatusUnsupportedMediaType,
						Message: "Content-Type must be application/json",
					})
					return
				}
			}

			// Validate request body size (max 10MB)
			r.Body = http.MaxBytesReader(w, r.Body, 10*1024*1024)

			next.ServeHTTP(w, r)
		})
	}
}
