package auth

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/crypto"

	stdjwt "github.com/dgrijalva/jwt-go"
)

type Auth interface {
	Kf(token *stdjwt.Token) (interface{}, error)
	KeycloakClaimsFactory() stdjwt.Claims
}

type auth struct {
	keycloakHost     string
	keycloakPort     string
	keycloakProtocol string
	keycloakRealm    string
	keycloakCA       string
}

type Roles struct {
	RoleNames []string `json:"roles"`
}

type Account struct {
	roles []Roles `json:"account"`
}

type KeycloakClaims struct {
	Type                      string   `json:"typ,omitempty"`
	AuthorizedParty           string   `json:"azp,omitempty"`
	Nonce                     string   `json:"nonce,omitempty"`
	AuthTime                  int64    `json:"auth_time,omitempty"`
	SessionState              string   `json:"session_state,omitempty"`
	AuthContextClassReference string   `json:"acr,omitempty"`
	AllowedOrigins            []string `json:"allowed-origins,omitempty"`
	RealmAccess               Roles    `json:"realm_access,omitempty"`
	ResourceAccess            Account  `json:"resource_access,omitempty"`
	Scope                     string   `json:"scope,omitempty"`
	EmailVerified             bool     `json:"email_verified,omitempty"`
	FullName                  string   `json:"name,omitempty"`
	PreferredUsername         string   `json:"preferred_username,omitempty"`
	GivenName                 string   `json:"given_name,omitempty"`
	FamilyName                string   `json:"family_name,omitempty"`
	Email                     string   `json:"email,omitempty"`
	stdjwt.StandardClaims
}

var (
	errBadKey              = errors.New("unexpected JWT key signing method")
	errBadPublicKeyRequest = errors.New("unable to obtain public key from Keycloak")
	errBadPublicKeyParse   = errors.New("unable to parse Keycloak public key")
	errKeycloakCA          = errors.New("error reading Keycloak CA")
)

type KeycloakPublic struct {
	Realm           string `json:"realm"`
	PublicKey       string `json:"public_key"`
	TokenService    string `json:"token-service"`
	AccountService  string `json:"account-service"`
	TokensNotBefore int    `json:"tokens-not-before"`
}

func NewAuth(keycloakHost string, keycloakPort string, keycloakProtocol string, keycloakRealm string, keycloakCA string) Auth {
	return &auth{keycloakHost: keycloakHost,
		keycloakPort:     keycloakPort,
		keycloakProtocol: keycloakProtocol,
		keycloakRealm:    keycloakRealm,
		keycloakCA:       keycloakCA,
	}
}

func (a *auth) KeycloakClaimsFactory() stdjwt.Claims {
	return &KeycloakClaims{}
}

func (a *auth) Kf(token *stdjwt.Token) (interface{}, error) {

	if _, ok := token.Method.(*stdjwt.SigningMethodRSA); !ok {
		return nil, errBadKey
	}

	keycloakURL := a.keycloakProtocol + "://" + a.keycloakHost + ":" + a.keycloakPort + "/auth/realms/" + a.keycloakRealm
	caCertPool, err := crypto.CreateCAPool(a.keycloakCA)
	if err != nil {
		return nil, errKeycloakCA
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	r, err := client.Get(keycloakURL)
	if err != nil {
		return nil, err
	}
	var keyPublic KeycloakPublic
	if err := json.NewDecoder(r.Body).Decode(&keyPublic); err != nil {
		return nil, errBadPublicKeyRequest
	}
	pubKey, err := crypto.ParseKeycloakPublicKey([]byte(crypto.PublicKeyHeader + "\n" + keyPublic.PublicKey + "\n" + crypto.PublicKeyFooter))
	if err != nil {
		return nil, errBadPublicKeyParse
	}
	return pubKey, nil
}
