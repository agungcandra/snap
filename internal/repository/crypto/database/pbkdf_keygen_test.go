package database_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/agungcandra/snap/internal/repository/crypto/database"
)

func TestPbkdf2Generator(t *testing.T) {
	t.Run("simplePassword", func(t *testing.T) {
		key, err := database.Pbkdf2Generator("lowEntropyKey")
		assert.Nil(t, err)
		assert.Len(t, key, 32)
	})

	t.Run("highEntropyPassword", func(t *testing.T) {
		password := "thisIsPasswordWithHighLevelOfEntropyBecauseItsSizeIsSoLongThatIHavingHardTimeToComeUpWithMessage"

		key, err := database.Pbkdf2Generator(password)
		assert.Nil(t, err)
		assert.Len(t, key, 32)
	})
}

func BenchmarkPbkdf2Generator(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = database.Pbkdf2Generator("randomPasswordGenerator")
	}
}
