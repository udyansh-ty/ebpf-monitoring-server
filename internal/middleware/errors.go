package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"
)

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

// ErrorHandlerMiddleware creates error handling middleware
func ErrorHandlerMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					fmt.Printf("panic: %v\n%s\n", err, debug.Stack())

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)

					json.NewEncoder(w).Encode(ErrorResponse{
						Error: "Internal Server Error",
						Code:  http.StatusInternalServerError,
					})
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}
