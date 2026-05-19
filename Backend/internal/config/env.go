package config

import (
	"os"
	"path/filepath"

	"github.com/joho/godotenv"
)

const EnvFileVar = "KNIG_ENV_FILE"

// LoadEnv loads the Backend runtime environment from one .env file.
//
// Resolution order:
//  1. KNIG_ENV_FILE, when explicitly set.
//  2. .env in the current working directory.
//  3. Backend/.env in the current working directory.
//  4. The nearest parent containing Backend/.env.
//
// Existing process environment values take precedence over file values.
func LoadEnv() error {
	if explicit := os.Getenv(EnvFileVar); explicit != "" {
		return godotenv.Load(explicit)
	}

	path, ok := findEnvFile()
	if !ok {
		return nil
	}
	return godotenv.Load(path)
}

func findEnvFile() (string, bool) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", false
	}

	candidates := []string{
		filepath.Join(cwd, ".env"),
		filepath.Join(cwd, "Backend", ".env"),
	}
	for _, path := range candidates {
		if isFile(path) {
			return path, true
		}
	}

	dir := cwd
	for {
		path := filepath.Join(dir, "Backend", ".env")
		if isFile(path) {
			return path, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
