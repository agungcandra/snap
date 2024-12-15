package signature_test

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/agungcandra/snap/internal/service/signature"
)

func BenchmarkPbkdf2Generator(b *testing.B) {
	salt := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, salt)

	fn := signature.Pbkdf2Generator("randomPasswordGenerator", salt)

	for i := 0; i < b.N; i++ {
		_, _ = fn()
	}
}

func TestPbkdf2Generator(t *testing.T) {
	salt := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, salt)

	otherSalt := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, salt)

	t.Run("simplePassword", func(t *testing.T) {
		key, err := signature.Pbkdf2Generator("lowEntropyKey", salt)()
		assert.Nil(t, err)
		assert.Len(t, key, 32)

		otherKey, err := signature.Pbkdf2Generator("lowEntropyKey", otherSalt)()
		assert.Nil(t, err)
		assert.Len(t, otherKey, 32)

		assert.NotEqual(t, key, otherKey)
	})

	t.Run("highEntropyPassword", func(t *testing.T) {
		password := "thisIsPasswordWithHighLevelOfEntropyBecauseItsSizeIsSoLongThatIHavingHardTimeToComeUpWithMessage"

		key, err := signature.Pbkdf2Generator(password, salt)()
		assert.Nil(t, err)
		assert.Len(t, key, 32)

		otherKey, err := signature.Pbkdf2Generator(password, otherSalt)()
		assert.Nil(t, err)
		assert.Len(t, key, 32)

		// different salt should generate different key, regardless password length
		assert.NotEqual(t, key, otherKey)
	})
}

func TestRandGenerator(t *testing.T) {
	keyLength := 32 // aes256 key length
	fn := signature.RandGenerator(keyLength)

	numTests := 1_000_000
	generatedKey := make(map[string]struct{})

	for i := 0; i < numTests; i++ {
		key, err := fn()
		assert.Nil(t, err)
		assert.NotEmpty(t, key)

		keyStr := string(key)
		if _, exists := generatedKey[keyStr]; exists {
			t.Errorf("Duplicate key generated at iteration %d", i)
		}

		generatedKey[keyStr] = struct{}{}
	}
}

func BenchmarkRandGenerator(b *testing.B) {
	fn := signature.RandGenerator(32)
	for i := 0; i < b.N; i++ {
		_, _ = fn()
	}
}
