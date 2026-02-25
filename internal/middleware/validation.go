package middleware

import (
	"encoding/json"
	"mime"
	"net/http"
)

// ValidationMiddleware creates request validation middleware
func ValidationMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// ANCHOR: JSON Content-Type Parsing - Bug: charset rejected - Feb 25, 2026
			// Accept application/json with optional parameters (e.g., charset) and reject others.
			// Validate Content-Type for POST/PUT requests
			if r.Method == http.MethodPost || r.Method == http.MethodPut {
				contentType := r.Header.Get("Content-Type")
				if contentType != "" {
					mediaType, _, err := mime.ParseMediaType(contentType)
					if err != nil {
						mediaType = contentType
					}
					if mediaType != "application/json" {
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
			}

			// Validate request body size (max 10MB)
			r.Body = http.MaxBytesReader(w, r.Body, 10*1024*1024)

			next.ServeHTTP(w, r)
		})
	}
}
