package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

// PasswordEntry represents a single password entry
type PasswordEntry struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// PasswordStore holds all password entries
type PasswordStore struct {
	Passwords map[string]PasswordEntry `json:"passwords"`
	FilePath  string
	Salt      []byte
}

// NewPasswordStore creates a new password store
func NewPasswordStore(filePath string) *PasswordStore {
	return &PasswordStore{
		Passwords: make(map[string]PasswordEntry),
		FilePath:  filePath,
	}
}

// deriveKey creates an encryption key from a master password
func deriveKey(masterPassword string, salt []byte) ([]byte, []byte) {
	if salt == nil {
		salt = make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			panic(err.Error())
		}
	}

	// Generate a 32-byte key using PBKDF2
	key := pbkdf2.Key([]byte(masterPassword), salt, 100000, 32, sha256.New)
	return key, salt
}

// SavePasswords encrypts and saves passwords to a file
func (ps *PasswordStore) SavePasswords(masterPassword string) error {
	// Convert passwords to JSON
	data, err := json.Marshal(ps.Passwords)
	if err != nil {
		return fmt.Errorf("error marshaling passwords: %w", err)
	}

	// Derive the encryption key
	key, salt := deriveKey(masterPassword, ps.Salt)
	ps.Salt = salt

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creating cipher: %w", err)
	}

	// Create a GCM (Galois/Counter Mode) cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error creating GCM: %w", err)
	}

	// Create a nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("error creating nonce: %w", err)
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// Create the directory if it doesn't exist
	dir := filepath.Dir(ps.FilePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("error creating directory: %w", err)
	}

	// Write the salt and encrypted data to file
	file, err := os.Create(ps.FilePath)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer file.Close()

	if _, err := file.Write(salt); err != nil {
		return fmt.Errorf("error writing salt: %w", err)
	}
	if _, err := file.Write(ciphertext); err != nil {
		return fmt.Errorf("error writing encrypted data: %w", err)
	}

	fmt.Printf("Passwords saved to %s\n", ps.FilePath)
	return nil
}

// LoadPasswords loads and decrypts passwords from a file
func (ps *PasswordStore) LoadPasswords(masterPassword string) error {
	// Check if the file exists
	if _, err := os.Stat(ps.FilePath); os.IsNotExist(err) {
		fmt.Printf("No existing password file found at %s\n", ps.FilePath)
		return nil
	}

	// Read the encrypted file
	data, err := ioutil.ReadFile(ps.FilePath)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	// First 16 bytes are the salt
	ps.Salt = data[:16]
	ciphertext := data[16:]

	// Derive the key from the master password and salt
	key, _ := deriveKey(masterPassword, ps.Salt)

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creating cipher: %w", err)
	}

	// Create a GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error creating GCM: %w", err)
	}

	// Verify that we have at least a nonce
	if len(ciphertext) < gcm.NonceSize() {
		return fmt.Errorf("ciphertext too short")
	}

	// Extract the nonce and ciphertext
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("error decrypting: %w", err)
	}

	// Parse the JSON
	if err := json.Unmarshal(plaintext, &ps.Passwords); err != nil {
		return fmt.Errorf("error unmarshaling passwords: %w", err)
	}

	fmt.Println("Passwords loaded successfully")
	return nil
}

// AddPassword adds or updates a password
func (ps *PasswordStore) AddPassword(service, username, password string) {
	ps.Passwords[service] = PasswordEntry{
		Username: username,
		Password: password,
	}
	fmt.Printf("Password for %s added/updated\n", service)
}

// GetPassword retrieves a password entry
func (ps *PasswordStore) GetPassword(service string) (PasswordEntry, bool) {
	entry, exists := ps.Passwords[service]
	if !exists {
		fmt.Printf("No password found for %s\n", service)
	}
	return entry, exists
}

// ListServices lists all stored services
func (ps *PasswordStore) ListServices() {
	if len(ps.Passwords) == 0 {
		fmt.Println("No passwords stored yet")
		return
	}

	fmt.Println("\nStored services:")
	i := 1
	for service, entry := range ps.Passwords {
		fmt.Printf("%d. %s (username: %s)\n", i, service, entry.Username)
		i++
	}
}

// DeletePassword deletes a password
func (ps *PasswordStore) DeletePassword(service string) bool {
	if _, exists := ps.Passwords[service]; exists {
		delete(ps.Passwords, service)
		fmt.Printf("Password for %s deleted\n", service)
		return true
	}
	fmt.Printf("No password found for %s\n", service)
	return false
}

// readPassword reads a password from the terminal without echoing
func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Add a newline after the password input
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(password)), nil
}

func main() {
	var filePath string
	if len(os.Args) > 1 {
		filePath = os.Args[1]
	} else {
		filePath = "passwords.enc"
	}

	store := NewPasswordStore(filePath)

	// Get the master password
	masterPassword, err := readPassword("Enter master password: ")
	if err != nil {
		fmt.Printf("Error reading password: %s\n", err)
		return
	}

	// Try to load existing passwords
	if err := store.LoadPasswords(masterPassword); err != nil {
		fmt.Printf("Error loading passwords: %s\n", err)
		fmt.Println("The file might be corrupted or the master password is incorrect")
		return
	}

	for {
		fmt.Println("\n----- Password Manager -----")
		fmt.Println("1. Add/Update password")
		fmt.Println("2. Get password")
		fmt.Println("3. List all services")
		fmt.Println("4. Delete password")
		fmt.Println("5. Save and exit")
		fmt.Println("6. Exit without saving")

		var choice string
		fmt.Print("\nEnter your choice (1-6): ")
		fmt.Scanln(&choice)

		switch choice {
		case "1":
			var service, username string
			fmt.Print("Enter service name: ")
			fmt.Scanln(&service)
			fmt.Print("Enter username: ")
			fmt.Scanln(&username)
			password, err := readPassword("Enter password: ")
			if err != nil {
				fmt.Printf("Error reading password: %s\n", err)
				continue
			}
			store.AddPassword(service, username, password)

		case "2":
			var service string
			fmt.Print("Enter service name: ")
			fmt.Scanln(&service)
			entry, exists := store.GetPassword(service)
			if exists {
				fmt.Printf("\nService: %s\n", service)
				fmt.Printf("Username: %s\n", entry.Username)
				fmt.Printf("Password: %s\n", entry.Password)
			}

		case "3":
			store.ListServices()

		case "4":
			var service string
			fmt.Print("Enter service name: ")
			fmt.Scanln(&service)
			store.DeletePassword(service)

		case "5":
			if err := store.SavePasswords(masterPassword); err != nil {
				fmt.Printf("Error saving passwords: %s\n", err)
			} else {
				fmt.Println("Goodbye!")
				return
			}

		case "6":
			fmt.Println("Exiting without saving. Any changes will be lost.")
			return

		default:
			fmt.Println("Invalid choice. Please try again.")
		}
	}
}
