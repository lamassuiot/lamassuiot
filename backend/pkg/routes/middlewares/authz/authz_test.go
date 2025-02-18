package authz

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	"github.com/sirupsen/logrus"
)

func TestAuthzMiddlewareRoles(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name               string
		endpoint           string
		expectedStatusCode int
		rolesInToken       []Role
	}

	publicEndpointTestCases := []testCase{
		{
			name:               "PublicEndpointNoToken",
			endpoint:           "/public",
			expectedStatusCode: 200,
			rolesInToken:       nil,
		},
		{
			name:               "PublicEndpointWithRoles",
			endpoint:           "/public",
			expectedStatusCode: 200,
			rolesInToken:       []Role{},
		},
	}

	superAdminEndpointTestCases := []testCase{
		{
			name:               "SuperAdminEndpointNoToken",
			endpoint:           "/super-admin",
			expectedStatusCode: 401,
			rolesInToken:       nil,
		},
		{
			name:               "SuperAdminEndpointWithSuperAdminRole",
			endpoint:           "/super-admin",
			expectedStatusCode: 200,
			rolesInToken:       []Role{RoleSuperAdmin},
		},
		{
			name:               "SuperAdminEndpointWithCAAdminRole",
			endpoint:           "/super-admin",
			expectedStatusCode: 403,
			rolesInToken:       []Role{RoleCAAdmin},
		},
	}

	caAdminEndpointTestCases := []testCase{
		{
			name:               "CAAdminEndpointNoToken",
			endpoint:           "/ca-admin",
			expectedStatusCode: 401,
			rolesInToken:       nil,
		},
		{
			name:               "CAAdminEndpointWithSuperAdminRole",
			endpoint:           "/ca-admin",
			expectedStatusCode: 200,
			rolesInToken:       []Role{RoleSuperAdmin},
		},
		{
			name:               "CAAdminEndpointWithCAAdminRole",
			endpoint:           "/ca-admin",
			expectedStatusCode: 200,
			rolesInToken:       []Role{RoleCAAdmin},
		},
		{
			name:               "CAAdminEndpointWithCAUser",
			endpoint:           "/ca-admin",
			expectedStatusCode: 403,
			rolesInToken:       []Role{RoleCAUser},
		},
		{
			name:               "CAAdminEndpointWithMultipleRolesWith1ValidRole",
			endpoint:           "/ca-admin",
			expectedStatusCode: 200,
			rolesInToken:       []Role{RoleCAUser, RoleCAAdmin},
		},
		{
			name:               "CAAdminEndpointWithMultipleRolesWithNoValidRole",
			endpoint:           "/ca-admin",
			expectedStatusCode: 403,
			rolesInToken:       []Role{RoleDeviceAdmin, RoleCAUser},
		},
	}

	caUserEndpointTestCases := []testCase{
		{
			name:               "CAUserEndpointNoToken",
			endpoint:           "/ca-user",
			expectedStatusCode: 401,
			rolesInToken:       nil,
		},
		{
			name:               "CAUserEndpointWithSuperAdminRole",
			endpoint:           "/ca-user",
			expectedStatusCode: 200,
			rolesInToken:       []Role{RoleSuperAdmin},
		},
		{
			name:               "CAUserEndpointWithCAAdminRole",
			endpoint:           "/ca-user",
			expectedStatusCode: 200,
			rolesInToken:       []Role{RoleCAAdmin},
		},
		{
			name:               "CAUserEndpointWithCAUser",
			endpoint:           "/ca-user",
			expectedStatusCode: 200,
			rolesInToken:       []Role{RoleCAUser},
		},
		{
			name:               "CAUserEndpointWithMultipleRolesWith2ValidRoles",
			endpoint:           "/ca-user",
			expectedStatusCode: 200,
			rolesInToken:       []Role{RoleCAUser, RoleCAAdmin},
		},
		{
			name:               "CAUserEndpointWithMultipleRolesWith1ValidRole",
			endpoint:           "/ca-user",
			expectedStatusCode: 200,
			rolesInToken:       []Role{RoleDeviceAdmin, RoleCAAdmin},
		},
		{
			name:               "CAUserEndpointWithInvalidRoles",
			endpoint:           "/ca-user",
			expectedStatusCode: 403,
			rolesInToken:       []Role{RoleDeviceAdmin, RoleDMSAdmin},
		},
	}

	tcases := append(publicEndpointTestCases, superAdminEndpointTestCases...)
	tcases = append(tcases, publicEndpointTestCases...)
	tcases = append(tcases, caUserEndpointTestCases...)
	tcases = append(tcases, caAdminEndpointTestCases...)

	port := lunchAuthzServer(t, DefaultRoleMapping)

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			// t.Parallel()

			req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost:%d%s", port, tc.endpoint), nil)
			if err != nil {
				t.Fatalf("could not create request: %s", err)
			}

			if tc.rolesInToken != nil {
				roles := []string{}
				for _, role := range tc.rolesInToken {
					roles = append(roles, string(role))
				}

				token := getToken(roles)
				req.Header.Set("Authorization", "Bearer "+token)
			}

			client := http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("could not send request: %s", err)
			}

			if resp.StatusCode != tc.expectedStatusCode {
				t.Fatalf("expected status code %d, got %d", tc.expectedStatusCode, resp.StatusCode)
			}
		})
	}
}
func TestAuthzMiddlewareCustomRoles(t *testing.T) {
	t.Parallel()

	customRoleMapping := map[Role]string{
		RoleSuperAdmin: "my_super_admin_role",
		RoleCAAdmin:    "my_ca_admin_role",
	}

	type testCase struct {
		name               string
		endpoint           string
		expectedStatusCode int
		rolesInToken       []string
	}

	tcases := []testCase{
		// {
		// 	name:               "CAAdminEndpoint",
		// 	endpoint:           "/ca-admin",
		// 	expectedStatusCode: 200,
		// 	rolesInToken:       []string{"my_ca_admin_role"},
		// },
		// {
		// 	name:               "CAAdminEndpointWithInvalidRole",
		// 	endpoint:           "/ca-admin",
		// 	expectedStatusCode: 403,
		// 	rolesInToken:       []string{"my_ca_admin_role_fake"},
		// },
		// {
		// 	name:               "SuperAdminEndpoint",
		// 	endpoint:           "/super-admin",
		// 	expectedStatusCode: 200,
		// 	rolesInToken:       []string{"my_super_admin_role"},
		// },
		// {
		// 	name:               "SuperAdminEndpointWithInvalidRole",
		// 	endpoint:           "/super-admin",
		// 	expectedStatusCode: 403,
		// 	rolesInToken:       []string{"my_super_admin_role_fake"},
		// },
		{
			name:               "CAUserEndpointWithDefaultRole",
			endpoint:           "/ca-user",
			expectedStatusCode: 200,
			rolesInToken:       []string{string(RoleCAUser)},
		},
		{
			name:               "CAUserEndpointWithInvalidRole",
			endpoint:           "/ca-user",
			expectedStatusCode: 403,
			rolesInToken:       []string{"my_ca_user_role"},
		},
	}

	port := lunchAuthzServer(t, customRoleMapping)

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			// t.Parallel()

			req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost:%d%s", port, tc.endpoint), nil)
			if err != nil {
				t.Fatalf("could not create request: %s", err)
			}

			if tc.rolesInToken != nil {
				roles := []string{}
				for _, role := range tc.rolesInToken {
					roles = append(roles, string(role))
				}

				token := getToken(roles)
				req.Header.Set("Authorization", "Bearer "+token)
			}

			client := http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("could not send request: %s", err)
			}

			if resp.StatusCode != tc.expectedStatusCode {
				t.Fatalf("expected status code %d, got %d", tc.expectedStatusCode, resp.StatusCode)
			}
		})
	}
}

func getToken(roles []string) string {
	claims := jwt.MapClaims{
		"nested_claims": map[string]interface{}{
			"roles": roles,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	return tokenString
}

func lunchAuthzServer(t *testing.T, roleMapping map[Role]string) int {
	lgr := logrus.New()
	lgr.SetOutput(io.Discard)
	// lgr.SetLevel(logrus.TraceLevel)

	logger := lgr.WithField("test", "Authz")

	baseController := func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{})
	}

	router := gin.New()
	router.Use(
		identityextractors.RequestMetadataToContextMiddleware(logger),
	)

	authzMw, err := NewAuthorizationMiddleware(logger, "nested_claims.roles", roleMapping, true)
	if err != nil {
		t.Fatalf("could not create authz middleware: %s", err)
	}

	router.GET("/public", baseController)
	router.GET("/super-admin", authzMw.Use([]Role{}), baseController)
	router.GET("/ca-admin", authzMw.Use([]Role{RoleCAAdmin}), baseController)
	router.GET("/ca-user", authzMw.Use([]Role{RoleCAAdmin, RoleCAUser}), baseController)

	addr := "0.0.0.0:0"
	//Run HTTP server
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("could not start listener: %s", err)
	}

	usedPort := listener.Addr().(*net.TCPAddr).Port
	server := http.Server{
		Addr:    addr,
		Handler: router,
	}

	t.Cleanup(func() {
		err = server.Close()
		if err != nil {
			t.Fatalf("could not close server: %s", err)
		}
	})

	go func() {
		err = server.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("could not start server: %s", err)
		}
	}()

	return usedPort
}
