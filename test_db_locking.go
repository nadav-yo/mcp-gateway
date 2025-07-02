package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/nadav-yo/mcp-gateway/internal/database"
)

func main() {
	// Initialize database
	db, err := database.New("test.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	fmt.Println("Testing database concurrency improvements...")

	// Test concurrent user creation
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			username := fmt.Sprintf("testuser%d", id)
			_, err := db.CreateUser(username, "password123")
			if err != nil {
				errors <- fmt.Errorf("failed to create user %s: %w", username, err)
			} else {
				fmt.Printf("Successfully created user: %s\n", username)
			}
		}(i)
	}

	// Test concurrent token creation
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			description := fmt.Sprintf("test token %d", id)
			_, err := db.CreateToken(1, "admin", description, nil, false)
			if err != nil {
				errors <- fmt.Errorf("failed to create token %d: %w", id, err)
			} else {
				fmt.Printf("Successfully created token: %s\n", description)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(errors)

	// Check for errors
	errorCount := 0
	for err := range errors {
		errorCount++
		fmt.Printf("Error: %v\n", err)
	}

	fmt.Printf("\nTest completed. Errors: %d\n", errorCount)
	if errorCount == 0 {
		fmt.Println("✅ All concurrent operations completed successfully!")
	} else {
		fmt.Println("❌ Some operations failed due to database locking issues")
	}
}
