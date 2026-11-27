package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/api/dto"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/store"
)

// replyBadRequest writes a 400 with a validation error detail. Used for both
// JSON binding failures and entity/request validation errors.
func replyBadRequest(c *gin.Context, err error) {
	c.JSON(http.StatusBadRequest, dto.ErrorResponse{
		Error:   "Invalid request",
		Details: map[string]string{"validation": err.Error()},
	})
}

// replyListError writes a 400 when a list request has a filter or sort the
// store cannot evaluate, and a 500 with the given message otherwise.
func replyListError(c *gin.Context, msg string, err error) {
	if errors.Is(err, store.ErrInvalidListQuery) {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid filter",
			Details: map[string]string{"error": err.Error()},
		})
		return
	}
	replyInternalError(c, msg, err)
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
func decodeJWTPayload(token string) (map[string]any, error) {
	return helpers.DecodeJWTPayload(token)
}
