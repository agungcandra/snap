package database_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/agungcandra/snap/internal/repository/crypto/database"
)

func TestRandomGenerator(t *testing.T) {
	keyLength := 32 // aes256 key length
	fn := database.RandomGenerator(keyLength)

	numTests := 1_000_000
	generatedKey := make(map[string]struct{})

	for i := 0; i < numTests; i++ {
		key, err := fn("")
		assert.Nil(t, err)
		assert.NotEmpty(t, key)

		keyStr := string(key)
		if _, exists := generatedKey[keyStr]; exists {
			t.Errorf("Duplicate key generated at iteration %d", i)
		}

		generatedKey[keyStr] = struct{}{}
	}
}

func BenchmarkRandomGenerator(b *testing.B) {
	fn := database.RandomGenerator(32)
	for i := 0; i < b.N; i++ {
		_, _ = fn("")
	}
}
