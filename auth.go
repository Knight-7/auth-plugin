package auth_plugin

import (
	"context"
	"net/http"

	"github.com/casbin/casbin/v2"
)

const (
	HeaderKey    = "Authorization"
	HeaderPrefix = "Bearer"
)

// Config auth plugin's configuration
type Config struct {
	Paths map[string]string `json:"paths,omitempty"`
}

// CreateConfig create auth plugin's configuration
func CreateConfig() *Config {
	return &Config{
		Paths: make(map[string]string),
	}
}

// Plugin auth plugin
type Plugin struct {
	next     http.Handler
	name     string
	enforcer *casbin.Enforcer
}

// New create a new auth plugin
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if _, ok := config.Paths["model"]; !ok {
		config.Paths["model"] = "./model.conf"
	}
	if _, ok := config.Paths["policy"]; !ok {
		config.Paths["policy"] = "./policy.csv"
	}

	e, err := casbin.NewEnforcer(config.Paths["model"], config.Paths["policy"])
	if err != nil {
		return nil, err
	}

	return &Plugin{
		name:     name,
		next:     next,
		enforcer: e,
	}, nil
}

func (p *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	authorization := req.Header.Get(HeaderKey)
	if authorization == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	claims, err := ParseToken(authorization[len(HeaderPrefix)+1:])
	if err != nil {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// rbac
	if ok, _ := p.enforcer.Enforce(claims.Role, req.URL.Path, req.Method); !ok {
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	p.next.ServeHTTP(rw, req)
}
