package service

import (
	stdjwt "github.com/dgrijalva/jwt-go"
)

type Roles struct {
	RoleNames []string `json:"roles"`
}

type LamssuAuthClaims struct {
	RealmAccess Roles `json:"realm_access,omitempty"`
	stdjwt.StandardClaims
}
