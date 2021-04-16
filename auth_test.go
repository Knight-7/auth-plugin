package auth_plugin_test

import (
	"context"
	"net/http"
	"testing"

	auth_plugin "github.com/Knight-7/auth-plugin"
	"github.com/stretchr/testify/assert"
)

func Test_auth(t *testing.T) {
	cfg := auth_plugin.CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	_, err := auth_plugin.New(ctx, next, cfg, "auth-plugin")
	assert.NoError(t, err)
}
