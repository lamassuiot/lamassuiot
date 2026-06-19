package controllers

import (
	"encoding/base64"
	"errors"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

type kmsV2HttpRoutes struct {
	svc cryptoenginesv2.Service
}

func NewKMSV2HttpRoutes(svc cryptoenginesv2.Service) *kmsV2HttpRoutes {
	return &kmsV2HttpRoutes{svc: svc}
}

// ---------------------------------------------------------------------------
// stateTransitionResponse is returned by PUT /v2/kms/keys/:id/state.
type stateTransitionResponse struct {
	KeyID          string                   `json:"id"`
	State          cryptoenginesv2.KeyState `json:"state"`
	PreviousState  cryptoenginesv2.KeyState `json:"previous_state"`
	TransitionedAt time.Time                `json:"transitioned_at"`
}

// handleKMSV2Error maps domain errors to HTTP status codes.
func handleKMSV2Error(ctx *gin.Context, err error) {
	switch {
	case errors.Is(err, cryptoenginesv2.ErrKeyNotFound),
		errors.Is(err, cryptoenginesv2.ErrAliasNotFound):
		ctx.JSON(404, gin.H{"err": err.Error()})
	case errors.Is(err, cryptoenginesv2.ErrAlgorithmNotSupported),
		errors.Is(err, cryptoenginesv2.ErrOperationNotAllowed):
		ctx.JSON(400, gin.H{"err": err.Error()})
	case errors.Is(err, cryptoenginesv2.ErrInvalidStateTransition):
		ctx.JSON(409, gin.H{"err": err.Error()})
	default:
		ctx.JSON(500, gin.H{"err": err.Error()})
	}
}

// ---------------------------------------------------------------------------
// GET /v2/kms/keys
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) ListKeys(ctx *gin.Context) {
	opts := cryptoenginesv2.ListOpts{
		PageToken: ctx.Query("page_token"),
		Filter:    ctx.Query("filter"),
	}
	if s := ctx.Query("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			opts.PageSize = n
		}
	}

	result, err := r.svc.ListKeys(ctx.Request.Context(), opts)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}

	keys := make([]cryptoenginesv2.KeyMetadata, len(result.Keys))
	for i, m := range result.Keys {
		keys[i] = (m)
	}
	ctx.JSON(200, gin.H{
		"keys":            keys,
		"next_page_token": result.NextPageToken,
	})
}

// ---------------------------------------------------------------------------
// POST /v2/kms/keys  (create or import)
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) CreateOrImportKey(ctx *gin.Context) {
	var body cryptoenginesv2.CreateKeyRequest
	if err := ctx.BindJSON(&body); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var (
		handle cryptoenginesv2.KeyHandle
		err    error
	)

	if body.KeyMaterial != "" {
		raw, decErr := base64.StdEncoding.DecodeString(body.KeyMaterial)
		if decErr != nil {
			ctx.JSON(400, gin.H{"err": "key_material: invalid base64: " + decErr.Error()})
			return
		}
		handle, err = r.svc.ImportKey(ctx.Request.Context(), cryptoenginesv2.ImportKeySpec{
			Algorithm:   body.Algorithm,
			Operations:  body.Operations,
			KeyMaterial: raw,
			Tags:        body.Tags,
			PolicyID:    body.PolicyID,
			NotBefore:   body.NotBefore,
			NotAfter:    body.NotAfter,
			BackendHint: body.BackendHint,
		})
	} else {
		handle, err = r.svc.CreateKey(ctx.Request.Context(), cryptoenginesv2.CreateKeySpec{
			Algorithm:  body.Algorithm,
			Operations: body.Operations,
			Tags:       body.Tags,
			PolicyID:    body.PolicyID,
			NotBefore:   body.NotBefore,
			NotAfter:    body.NotAfter,
			BackendHint: body.BackendHint,
		})
	}

	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}
	defer handle.Close()

	ctx.JSON(201, handle.Metadata())
}

// ---------------------------------------------------------------------------
// GET /v2/kms/keys/:id  (UUID or alias — resolved transparently)
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) GetKey(ctx *gin.Context) {
	type uriP struct {
		ID string `uri:"id" binding:"required"`
	}
	var p uriP
	if err := ctx.ShouldBindUri(&p); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	handle, err := r.resolveKey(ctx, p.ID)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}
	defer handle.Close()

	ctx.JSON(200, handle.Metadata())
}

// ---------------------------------------------------------------------------
// PATCH /v2/kms/keys/:id  (metadata only — never state)
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) UpdateKey(ctx *gin.Context) {
	type uriP struct {
		ID string `uri:"id" binding:"required"`
	}
	var p uriP
	if err := ctx.ShouldBindUri(&p); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var body cryptoenginesv2.UpdateKeyRequest
	if err := ctx.BindJSON(&body); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	meta, err := r.svc.UpdateKey(ctx.Request.Context(), cryptoenginesv2.KeyID(p.ID), cryptoenginesv2.KeyPatch{
		Tags:    body.Tags,
		PolicyID:    body.PolicyID,
		NotAfter:    body.NotAfter,
	})
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}

	ctx.JSON(200, meta)
}

// ---------------------------------------------------------------------------
// DELETE /v2/kms/keys/:id  (soft-delete: schedules destruction, 202)
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) DeleteKey(ctx *gin.Context) {
	type uriP struct {
		ID string `uri:"id" binding:"required"`
	}
	var p uriP
	if err := ctx.ShouldBindUri(&p); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	// Default window: 7 days. Callers may override via ?pending_days=N.
	days := 7
	if s := ctx.Query("pending_days"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			days = n
		}
	}

	err := r.svc.ScheduleDeletion(ctx.Request.Context(),
		cryptoenginesv2.KeyID(p.ID),
		time.Duration(days)*24*time.Hour,
	)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}

	ctx.JSON(202, gin.H{"id": p.ID, "state": string(cryptoenginesv2.StatePendingDelete)})
}

// ---------------------------------------------------------------------------
// PUT /v2/kms/keys/:id/state
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) SetKeyState(ctx *gin.Context) {
	type uriP struct {
		ID string `uri:"id" binding:"required"`
	}
	var p uriP
	if err := ctx.ShouldBindUri(&p); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var body cryptoenginesv2.SetKeyStateRequest
	if err := ctx.BindJSON(&body); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	id := cryptoenginesv2.KeyID(p.ID)
	goCtx := ctx.Request.Context()

	// Fetch current state to dispatch to the correct service method.
	current, err := r.svc.GetKey(goCtx, id)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}
	fromState := current.Metadata().State
	current.Close()

	switch body.State {
	case cryptoenginesv2.StateEnabled:
		err = r.svc.EnableKey(goCtx, id)

	case cryptoenginesv2.StateDisabled:
		if fromState == cryptoenginesv2.StatePendingDelete {
			err = r.svc.CancelDeletion(goCtx, id)
		} else {
			err = r.svc.DisableKey(goCtx, id)
		}

	case cryptoenginesv2.StatePendingDelete:
		if body.DeletionScheduledAt == nil {
			ctx.JSON(400, gin.H{"err": "deletion_scheduled_at is required when state is pendingDeletion"})
			return
		}
		after := time.Until(*body.DeletionScheduledAt)
		if after <= 0 {
			ctx.JSON(400, gin.H{"err": "deletion_scheduled_at must be in the future"})
			return
		}
		err = r.svc.ScheduleDeletion(goCtx, id, after)

	default:
		ctx.JSON(400, gin.H{"err": "invalid target state: " + string(body.State)})
		return
	}

	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}

	ctx.JSON(200, stateTransitionResponse{
		KeyID:          p.ID,
		State:          body.State,
		PreviousState:  fromState,
		TransitionedAt: time.Now(),
	})
}

// ---------------------------------------------------------------------------
// PUT /v2/kms/keys/:id/backup
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) BackupKey(ctx *gin.Context) {
	type uriP struct {
		ID string `uri:"id" binding:"required"`
	}
	var p uriP
	if err := ctx.ShouldBindUri(&p); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	blob, err := r.svc.BackupKey(ctx.Request.Context(), cryptoenginesv2.KeyID(p.ID))
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}

	ctx.JSON(200, gin.H{
		"key_id":      p.ID,
		"backup_blob": base64.StdEncoding.EncodeToString(blob.Bytes),
	})
}

// ---------------------------------------------------------------------------
// POST /v2/kms/keys/restore
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) RestoreKey(ctx *gin.Context) {
	var body cryptoenginesv2.RestoreKeyRequest
	if err := ctx.BindJSON(&body); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	raw, err := base64.StdEncoding.DecodeString(body.BackupBlob)
	if err != nil {
		ctx.JSON(400, gin.H{"err": "backup_blob: invalid base64: " + err.Error()})
		return
	}

	handle, err := r.svc.RestoreKey(ctx.Request.Context(), cryptoenginesv2.BackupBlob{Bytes: raw})
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}
	defer handle.Close()

	ctx.JSON(200, handle.Metadata())
}

// ---------------------------------------------------------------------------
// PUT /v2/kms/aliases/:name  (upsert — create or retarget atomically)
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) UpsertAlias(ctx *gin.Context) {
	type uriP struct {
		Name string `uri:"name" binding:"required"`
	}
	var p uriP
	if err := ctx.ShouldBindUri(&p); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var body cryptoenginesv2.UpsertAliasRequest
	if err := ctx.BindJSON(&body); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	// CreateAlias is expected to have upsert semantics at the store layer
	// (PutAlias overwrites). No delete-then-recreate needed here.
	if err := r.svc.CreateAlias(ctx.Request.Context(), p.Name, cryptoenginesv2.KeyID(body.KeyID)); err != nil {
		handleKMSV2Error(ctx, err)
		return
	}

	ctx.JSON(200, gin.H{"name": p.Name, "key_id": body.KeyID})
}

// ---------------------------------------------------------------------------
// DELETE /v2/kms/aliases/:name
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) DeleteAlias(ctx *gin.Context) {
	type uriP struct {
		Name string `uri:"name" binding:"required"`
	}
	var p uriP
	if err := ctx.ShouldBindUri(&p); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	if err := r.svc.DeleteAlias(ctx.Request.Context(), p.Name); err != nil {
		handleKMSV2Error(ctx, err)
		return
	}

	ctx.Status(204)
}

// ---------------------------------------------------------------------------
// GET /v2/kms/aliases/:name  (resolves alias → full key metadata)
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) ResolveAlias(ctx *gin.Context) {
	type uriP struct {
		Name string `uri:"name" binding:"required"`
	}
	var p uriP
	if err := ctx.ShouldBindUri(&p); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	id, err := r.svc.ResolveAlias(ctx.Request.Context(), p.Name)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}

	handle, err := r.svc.GetKey(ctx.Request.Context(), id)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}
	defer handle.Close()

	ctx.JSON(200, handle.Metadata())
}

// ---------------------------------------------------------------------------
// POST /v2/kms/random
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) GenerateRandom(ctx *gin.Context) {
	var body cryptoenginesv2.GenerateRandomRequest
	if err := ctx.BindJSON(&body); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	data, err := r.svc.GenerateRandom(ctx.Request.Context(), body.Bytes)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}

	ctx.JSON(200, gin.H{
		"bytes": body.Bytes,
		"data":  base64.StdEncoding.EncodeToString(data),
	})
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

// resolveKey tries GetKey(id) first; if the key is not found it treats id as
// an alias name and calls ResolveAlias + GetKey — transparent resolution.
func (r *kmsV2HttpRoutes) resolveKey(ctx *gin.Context, id string) (cryptoenginesv2.KeyHandle, error) {
	handle, err := r.svc.GetKey(ctx.Request.Context(), cryptoenginesv2.KeyID(id))
	if err == nil {
		return handle, nil
	}
	if !errors.Is(err, cryptoenginesv2.ErrKeyNotFound) {
		return nil, err
	}

	// Not a direct key ID — try alias resolution.
	resolved, aliasErr := r.svc.ResolveAlias(ctx.Request.Context(), id)
	if aliasErr != nil {
		return nil, err // return original ErrKeyNotFound, not the alias error
	}
	return r.svc.GetKey(ctx.Request.Context(), resolved)
}
