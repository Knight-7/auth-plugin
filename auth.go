package auth_plugin

/*
import (
	"context"
	"net/http"

	"github.com/casbin/casbin/v2"
)

// Config auth plugin's configuration
type Config struct {}

// CreateConfig create auth plugin's configuration
func CreateConfig() *Config {
	return &Config{}
}

// Plugin auth plugin
type Plugin struct {
	next     http.Handler
	name     string
	enforcer *casbin.Enforcer
}

// New create a new auth plugin
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	if config.ModelPath == "" {
		config.ModelPath = "./model.conf"
	}
	if config.PolicyPath == "" {
		config.PolicyPath = "./policy.csv"
	}



	e, err := casbin.NewEnforcer("./model.conf", "./policy.csv")
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
	authorization := req.Header.Get("Authorization")
	if authorization == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	claims, err := ParseToken(authorization[len("Bearer")+1:])
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
*/

import (
	"context"
	"net/http"
)

// Config the plugin configuration.
type Config struct {
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// Demo a Demo plugin.
type Demo struct {
	next http.Handler
	name string
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Demo{
		next: next,
		name: name,
	}, nil
}

func (a *Demo) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("middleware", "demo")
	a.next.ServeHTTP(rw, req)
}
