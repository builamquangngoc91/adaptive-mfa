package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHealth(t *testing.T) {

	t.Run("success", func(t *testing.T) {
		healthController := NewHealthController()

		health, err := healthController.Health(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, "OK", health.Status)
	})
}

