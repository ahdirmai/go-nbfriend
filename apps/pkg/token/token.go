package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type PayloadToken struct {
	AuthId  int
	Expired time.Time
}

const SecretKey = "7RtOKaDLD3BsGbVm7znXd2bDjJ0PG6vd"

func GenerateToken(tok *PayloadToken) (string, error) {
	tok.Expired = time.Now().Add(10 * 60 * time.Second)
	claims := jwt.MapClaims{
		"payload": tok,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(SecretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ValidateToken(tokString string) (*PayloadToken, error) {
	tok, err := jwt.Parse(tokString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(SecretKey), nil
	})
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return nil, errors.New("Malformed token")
			} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				return nil, errors.New("Token is expired or not valid yet")
			} else {
				return nil, errors.New("Token validation error")
			}
		} else {
			return nil, errors.New("Token parsing error")
		}
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, errors.New("Unauthorized")
	}

	payload := claims["payload"]
	payloadMap, ok := payload.(map[string]interface{})
	if !ok {
		return nil, errors.New("Invalid Payload type")
	}

	authID, ok := payloadMap["AuthId"].(float64)
	if !ok {
		return nil, errors.New("Invalid AuthId type")
	}

	expiredStr, ok := payloadMap["Expired"].(string)
	if !ok {
		return nil, errors.New("Invalid Expired type")
	}

	expiredTime, err := time.Parse(time.RFC3339, expiredStr)
	if err != nil {
		return nil, errors.New("Invalid Expired time format")
	}

	payloadToken := &PayloadToken{
		AuthId:  int(authID),
		Expired: expiredTime,
	}

	return payloadToken, nil
}
