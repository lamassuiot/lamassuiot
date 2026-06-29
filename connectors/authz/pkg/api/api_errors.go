package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/api/dto"
	"github.com/lamassuiot/lamassuiot/pki/v3/pkg/helpers"
)

// replyBadRequest writes a 400 with a validation error detail. Used for both
// JSON binding failures and entity/request validation errors.
func replyBadRequest(c *gin.Context, err error) {
	c.JSON(http.StatusBadRequest, dto.ErrorResponse{
		Error:   "Invalid request",
		Details: map[string]string{"validation": err.Error()},
	})
}

// replyInternalError writes a 500 with the given message and error detail.
func replyInternalError(c *gin.Context, msg string, err error) {
	c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
		Error:   msg,
		Details: map[string]string{"error": err.Error()},
	})
}

// replyPolicyNotFound writes a 404 when err matches "policy not found: {id}".
// Returns true if it did so (so callers can `if replyPolicyNotFound(...) { return }`).
func replyPolicyNotFound(c *gin.Context, err error, policyID string) bool {
	if err == nil || err.Error() != "policy not found: "+policyID {
		return false
	}
	c.JSON(http.StatusNotFound, dto.ErrorResponse{
		Error:   "Policy not found",
		Details: map[string]string{"policyId": policyID},
	})
	return true
}

// decodeJWTPayload extracts claims from a JWT token for log context enrichment.
// No signature verification is performed — auth uses OIDCMatcher with full verification.
func decodeJWTPayload(token string) (map[string]interface{}, error) {
	return helpers.DecodeJWTPayload(token)
}
