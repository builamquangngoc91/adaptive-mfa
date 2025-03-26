package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func BenchmarkRegister(b *testing.B) {
	for i := 0; i < b.N; i++ {
		fullname := fmt.Sprintf("test%s", uuid.New().String())
		username := fmt.Sprintf("test%s", uuid.New().String())
		password := "password"
		callApiRegister(b, fullname, username, password)
	}
}

func callApiRegister(b *testing.B, fullname, email, password string) {
	// Create a request body
	requestBody := map[string]interface{}{
		"fullname": fullname,
		"email":    email,
		"password": password,
	}

	// Convert the body to JSON
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		b.Fatalf("Failed to marshal JSON: %v", err)
	}

	// Create a new HTTP POST request
	req, err := http.NewRequest("POST", "http://amfa-test:8083/v1/auth/register", bytes.NewBuffer(jsonBody))
	if err != nil {
		b.Fatalf("Failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Create an HTTP client and send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		b.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Read and process the response if needed
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		b.Fatalf("Failed to read response: %v", err)
	}
}

func callApiLogin(b *testing.B, email, password string) {
	// Create a request body
	requestBody := map[string]interface{}{
		"email":    email,
		"password": password,
	}

	// Convert the body to JSON
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		b.Fatalf("Failed to marshal JSON: %v", err)
	}

	// Create a new HTTP POST request
	req, err := http.NewRequest("POST", "http://amfa-test:8083/v1/auth/login", bytes.NewBuffer(jsonBody))
	if err != nil {
		b.Fatalf("Failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Create an HTTP client and send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		b.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Read and process the response if needed
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		b.Fatalf("Failed to read response: %v", err)
	}
}

func BenchmarkLogin(b *testing.B) {
	ids := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		id := uuid.New().String()
		fullname := fmt.Sprintf("test%s", id)
		email := fmt.Sprintf("test%s@test.com", id)
		password := "password"
		ids[i] = id

		callApiRegister(b, fullname, email, password)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := ids[i]
		email := fmt.Sprintf("test%s@test.com", id)
		password := "password"
		callApiLogin(b, email, password)
	}
}
