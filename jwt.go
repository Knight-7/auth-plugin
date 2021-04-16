package auth_plugin

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	// TokenExpireDuration token expire duration
	TokenExpireDuration = time.Hour * 2
)

var (
	// TokenSecret token secret
	TokenSecret = []byte("Secret")
)

// MyClaims a jwt claims
type MyClaims struct {
	Username string `json:"username"`
	Passwd   string `json:"passwd"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

func GenToken(username, passwd, role string) (string, error) {
	c := &MyClaims{
		username,
		passwd,
		role,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(TokenExpireDuration).Unix(),
			Issuer:    "auth-demo",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)

	return token.SignedString(TokenSecret)
}

func ParseToken(tokenString string) (*MyClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &MyClaims{}, func(token *jwt.Token) (interface{}, error) {
		return TokenSecret, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*MyClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
