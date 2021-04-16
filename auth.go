package auth_plugin

import (
	"context"
	"net/http"

	"github.com/casbin/casbin/v2"
)

// Config auth plugin's configuration
type Config struct {
	CasbinModelPath string
	CasbinPolicyPath string
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
	e, err := casbin.NewEnforcer(config.CasbinModelPath, config.CasbinPolicyPath)
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

/*
func unauthorized(rw http.ResponseWriter, err error) {
	rw.Header().Set("Content-Type", "application/json")
	data := map[string]interface{}{
		"code": http.StatusUnauthorized,
		"msg":  err.Error(),
	}

	byteData, err := json.Marshal(data)
	rw.Write(byteData)
}
*/
