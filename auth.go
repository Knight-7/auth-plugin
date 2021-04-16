package auth_plugin


import (
	"context"
	"net/http"

	"github.com/casbin/casbin/v2"
)

// Config auth plugin's configuration
type Config struct {
	ModelPath string `json:"modelPath,omitempty"`
	PolicyPath string `json:"policyPath,omitempty"`
}

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



	e, err := casbin.NewEnforcer(config.ModelPath, config.PolicyPath)
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
