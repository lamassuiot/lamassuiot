package controllers

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
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
			KeySpec:     body.KeySpec,
			Operations:  body.Operations,
			KeyUsages:   body.KeyUsages,
			KeyMaterial: raw,
			Tags:        body.Tags,
			PolicyID:    body.PolicyID,
			NotBefore:   body.NotBefore,
			NotAfter:    body.NotAfter,
			BackendHint: body.BackendHint,
		})
	} else {
		handle, err = r.svc.CreateKey(ctx.Request.Context(), cryptoenginesv2.CreateKeySpec{
			KeySpec:     body.KeySpec,
			Operations:  body.Operations,
			KeyUsages:   body.KeyUsages,
			Tags:        body.Tags,
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
		Tags:     body.Tags,
		PolicyID: body.PolicyID,
		NotAfter: body.NotAfter,
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

// ===========================================================================
// Cryptographic operations
//
// Each handler resolves the key (by ID or alias), type-asserts the returned
// KeyHandle to the capability interface the operation requires, and returns a
// 400 if the key does not support it. Binary payloads are base64-encoded.
// ===========================================================================

// ---------------------------------------------------------------------------
// POST /v2/kms/keys/:id/sign
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) Sign(ctx *gin.Context) {
	id, ok := bindKeyID(ctx)
	if !ok {
		return
	}

	var body cryptoenginesv2.SignRequest
	if err := ctx.BindJSON(&body); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}
	digest, ok := decodeB64(ctx, "digest", body.Digest)
	if !ok {
		return
	}

	handle, err := r.resolveKey(ctx, id)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}
	defer handle.Close()

	signer, ok := handle.(cryptoenginesv2.Signer)
	if !ok {
		opNotSupported(ctx, string(cryptoenginesv2.OpSign))
		return
	}

	sig, err := signer.SignContext(ctx.Request.Context(), digest, body.Algorithm, hashForAlg(body.Algorithm))
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}

	ctx.JSON(200, cryptoenginesv2.SignResponse{
		KeyID:     id,
		Algorithm: body.Algorithm,
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
}

// ---------------------------------------------------------------------------
// POST /v2/kms/keys/:id/verify
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) Verify(ctx *gin.Context) {
	id, ok := bindKeyID(ctx)
	if !ok {
		return
	}

	var body cryptoenginesv2.VerifyRequest
	if err := ctx.BindJSON(&body); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}
	digest, ok := decodeB64(ctx, "digest", body.Digest)
	if !ok {
		return
	}
	sig, ok := decodeB64(ctx, "signature", body.Signature)
	if !ok {
		return
	}

	handle, err := r.resolveKey(ctx, id)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}
	defer handle.Close()

	verifier, ok := handle.(cryptoenginesv2.Verifier)
	if !ok {
		opNotSupported(ctx, string(cryptoenginesv2.OpVerify))
		return
	}

	err = verifier.Verify(ctx.Request.Context(), digest, sig, body.Algorithm, hashForAlg(body.Algorithm))
	// A verification mismatch is a valid 200 result (valid:false), not an error;
	// only surface transport/key errors as HTTP failures.
	if err != nil && !isVerifyMismatch(err) {
		handleKMSV2Error(ctx, err)
		return
	}

	ctx.JSON(200, cryptoenginesv2.VerifyResponse{KeyID: id, Valid: err == nil})
}

// ---------------------------------------------------------------------------
// POST /v2/kms/keys/:id/encrypt  (asymmetric or symmetric)
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) Encrypt(ctx *gin.Context) {
	id, ok := bindKeyID(ctx)
	if !ok {
		return
	}

	var body cryptoenginesv2.EncryptRequest
	if err := ctx.BindJSON(&body); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}
	plaintext, ok := decodeB64(ctx, "plaintext", body.Plaintext)
	if !ok {
		return
	}
	aad, ok := decodeOptionalB64(ctx, "associated_data", body.AssociatedData)
	if !ok {
		return
	}

	handle, err := r.resolveKey(ctx, id)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}
	defer handle.Close()

	goCtx := ctx.Request.Context()

	// Asymmetric encryption (RSAES_OAEP_*) takes precedence; fall back to the
	// symmetric AEAD path for SYMMETRIC_DEFAULT keys.
	if enc, ok := handle.(cryptoenginesv2.Encrypter); ok {
		out, err := enc.EncryptContext(goCtx, plaintext, body.Algorithm, cryptoenginesv2.EncryptOpts{AssociatedData: aad})
		if err != nil {
			handleKMSV2Error(ctx, err)
			return
		}
		ctx.JSON(200, cryptoenginesv2.EncryptResponse{
			KeyID:      id,
			Algorithm:  body.Algorithm,
			Ciphertext: base64.StdEncoding.EncodeToString(out),
		})
		return
	}

	if sym, ok := handle.(cryptoenginesv2.SymmetricCipher); ok {
		nonce, ok := decodeOptionalB64(ctx, "nonce", body.Nonce)
		if !ok {
			return
		}
		ct, err := sym.Encrypt(goCtx, plaintext, body.Algorithm, cryptoenginesv2.SymmetricOpts{Nonce: nonce, AssociatedData: aad})
		if err != nil {
			handleKMSV2Error(ctx, err)
			return
		}
		ctx.JSON(200, cryptoenginesv2.EncryptResponse{
			KeyID:      id,
			Algorithm:  ct.Algorithm,
			Ciphertext: base64.StdEncoding.EncodeToString(ct.Bytes),
			Nonce:      base64.StdEncoding.EncodeToString(ct.Nonce),
		})
		return
	}

	opNotSupported(ctx, string(cryptoenginesv2.OpEncrypt))
}

// ---------------------------------------------------------------------------
// POST /v2/kms/keys/:id/decrypt  (asymmetric or symmetric)
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) Decrypt(ctx *gin.Context) {
	id, ok := bindKeyID(ctx)
	if !ok {
		return
	}

	var body cryptoenginesv2.DecryptRequest
	if err := ctx.BindJSON(&body); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}
	ciphertext, ok := decodeB64(ctx, "ciphertext", body.Ciphertext)
	if !ok {
		return
	}
	aad, ok := decodeOptionalB64(ctx, "associated_data", body.AssociatedData)
	if !ok {
		return
	}

	handle, err := r.resolveKey(ctx, id)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}
	defer handle.Close()

	goCtx := ctx.Request.Context()

	if dec, ok := handle.(cryptoenginesv2.Decrypter); ok {
		// For RSA-OAEP, associated_data carries the OAEP label and must match
		// the value supplied at encrypt time; forward it via OAEPOptions.
		var opts crypto.DecrypterOpts
		if len(aad) > 0 {
			opts = &rsa.OAEPOptions{Label: aad}
		}
		out, err := dec.DecryptContext(goCtx, ciphertext, body.Algorithm, opts)
		if err != nil {
			handleKMSV2Error(ctx, err)
			return
		}
		ctx.JSON(200, cryptoenginesv2.DecryptResponse{
			KeyID:     id,
			Plaintext: base64.StdEncoding.EncodeToString(out),
		})
		return
	}

	if sym, ok := handle.(cryptoenginesv2.SymmetricCipher); ok {
		nonce, ok := decodeOptionalB64(ctx, "nonce", body.Nonce)
		if !ok {
			return
		}
		out, err := sym.Decrypt(goCtx, cryptoenginesv2.Ciphertext{
			Algorithm: body.Algorithm,
			Nonce:     nonce,
			Bytes:     ciphertext,
			AAD:       aad,
		}, cryptoenginesv2.SymmetricOpts{Nonce: nonce, AssociatedData: aad})
		if err != nil {
			handleKMSV2Error(ctx, err)
			return
		}
		ctx.JSON(200, cryptoenginesv2.DecryptResponse{
			KeyID:     id,
			Plaintext: base64.StdEncoding.EncodeToString(out),
		})
		return
	}

	opNotSupported(ctx, string(cryptoenginesv2.OpDecrypt))
}

// ---------------------------------------------------------------------------
// POST /v2/kms/keys/:id/mac
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) MAC(ctx *gin.Context) {
	id, ok := bindKeyID(ctx)
	if !ok {
		return
	}

	var body cryptoenginesv2.MACRequest
	if err := ctx.BindJSON(&body); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}
	message, ok := decodeB64(ctx, "message", body.Message)
	if !ok {
		return
	}

	handle, err := r.resolveKey(ctx, id)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}
	defer handle.Close()

	macer, ok := handle.(cryptoenginesv2.MACer)
	if !ok {
		opNotSupported(ctx, string(cryptoenginesv2.OpMAC))
		return
	}

	mac, err := macer.MAC(ctx.Request.Context(), message, body.Algorithm)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}

	ctx.JSON(200, cryptoenginesv2.MACResponse{
		KeyID:     id,
		Algorithm: body.Algorithm,
		MAC:       base64.StdEncoding.EncodeToString(mac),
	})
}

// ---------------------------------------------------------------------------
// POST /v2/kms/keys/:id/verify-mac
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) VerifyMAC(ctx *gin.Context) {
	id, ok := bindKeyID(ctx)
	if !ok {
		return
	}

	var body cryptoenginesv2.VerifyMACRequest
	if err := ctx.BindJSON(&body); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}
	message, ok := decodeB64(ctx, "message", body.Message)
	if !ok {
		return
	}
	mac, ok := decodeB64(ctx, "mac", body.MAC)
	if !ok {
		return
	}

	handle, err := r.resolveKey(ctx, id)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}
	defer handle.Close()

	macer, ok := handle.(cryptoenginesv2.MACer)
	if !ok {
		opNotSupported(ctx, string(cryptoenginesv2.OpVerifyMAC))
		return
	}

	err = macer.VerifyMAC(ctx.Request.Context(), message, mac, body.Algorithm)
	if err != nil && !isVerifyMismatch(err) {
		handleKMSV2Error(ctx, err)
		return
	}

	ctx.JSON(200, cryptoenginesv2.VerifyMACResponse{KeyID: id, Valid: err == nil})
}

// ---------------------------------------------------------------------------
// POST /v2/kms/keys/:id/wrap
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) WrapKey(ctx *gin.Context) {
	id, ok := bindKeyID(ctx)
	if !ok {
		return
	}

	var body cryptoenginesv2.WrapKeyRequest
	if err := ctx.BindJSON(&body); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}
	keyMaterial, ok := decodeB64(ctx, "key_material", body.KeyMaterial)
	if !ok {
		return
	}
	aad, ok := decodeOptionalB64(ctx, "associated_data", body.AssociatedData)
	if !ok {
		return
	}

	handle, err := r.resolveKey(ctx, id)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}
	defer handle.Close()

	wrapper, ok := handle.(cryptoenginesv2.KeyWrapper)
	if !ok {
		opNotSupported(ctx, string(cryptoenginesv2.OpWrapKey))
		return
	}

	wrapped, err := wrapper.WrapKey(ctx.Request.Context(), keyMaterial, body.Algorithm, cryptoenginesv2.WrapOpts{AssociatedData: aad})
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}

	ctx.JSON(200, cryptoenginesv2.WrapKeyResponse{
		KeyID:      id,
		Algorithm:  body.Algorithm,
		WrappedKey: base64.StdEncoding.EncodeToString(wrapped),
	})
}

// ---------------------------------------------------------------------------
// POST /v2/kms/keys/:id/unwrap
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) UnwrapKey(ctx *gin.Context) {
	id, ok := bindKeyID(ctx)
	if !ok {
		return
	}

	var body cryptoenginesv2.UnwrapKeyRequest
	if err := ctx.BindJSON(&body); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}
	wrapped, ok := decodeB64(ctx, "wrapped_key", body.WrappedKey)
	if !ok {
		return
	}
	aad, ok := decodeOptionalB64(ctx, "associated_data", body.AssociatedData)
	if !ok {
		return
	}

	handle, err := r.resolveKey(ctx, id)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}
	defer handle.Close()

	wrapper, ok := handle.(cryptoenginesv2.KeyWrapper)
	if !ok {
		opNotSupported(ctx, string(cryptoenginesv2.OpUnwrapKey))
		return
	}

	keyMaterial, err := wrapper.UnwrapKey(ctx.Request.Context(), wrapped, body.Algorithm, cryptoenginesv2.WrapOpts{AssociatedData: aad})
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}

	ctx.JSON(200, cryptoenginesv2.UnwrapKeyResponse{
		KeyID:       id,
		KeyMaterial: base64.StdEncoding.EncodeToString(keyMaterial),
	})
}

// ---------------------------------------------------------------------------
// POST /v2/kms/keys/:id/encapsulate  (KEM)
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) Encapsulate(ctx *gin.Context) {
	id, ok := bindKeyID(ctx)
	if !ok {
		return
	}

	handle, err := r.resolveKey(ctx, id)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}
	defer handle.Close()

	encap, ok := handle.(cryptoenginesv2.Encapsulator)
	if !ok {
		opNotSupported(ctx, string(cryptoenginesv2.OpEncapsulate))
		return
	}

	sharedSecret, ciphertext, err := encap.EncapsulateContext(ctx.Request.Context())
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}

	ctx.JSON(200, cryptoenginesv2.EncapsulateResponse{
		KeyID:        id,
		SharedSecret: base64.StdEncoding.EncodeToString(sharedSecret),
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
	})
}

// ---------------------------------------------------------------------------
// POST /v2/kms/keys/:id/decapsulate  (KEM)
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) Decapsulate(ctx *gin.Context) {
	id, ok := bindKeyID(ctx)
	if !ok {
		return
	}

	var body cryptoenginesv2.DecapsulateRequest
	if err := ctx.BindJSON(&body); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}
	ciphertext, ok := decodeB64(ctx, "ciphertext", body.Ciphertext)
	if !ok {
		return
	}

	handle, err := r.resolveKey(ctx, id)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}
	defer handle.Close()

	decap, ok := handle.(cryptoenginesv2.Decapsulator)
	if !ok {
		opNotSupported(ctx, string(cryptoenginesv2.OpDecapsulate))
		return
	}

	sharedSecret, err := decap.DecapsulateContext(ctx.Request.Context(), ciphertext)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}

	ctx.JSON(200, cryptoenginesv2.DecapsulateResponse{
		KeyID:        id,
		SharedSecret: base64.StdEncoding.EncodeToString(sharedSecret),
	})
}

// ---------------------------------------------------------------------------
// POST /v2/kms/keys/:id/agree  (key agreement, optionally with KDF)
// ---------------------------------------------------------------------------

func (r *kmsV2HttpRoutes) Agree(ctx *gin.Context) {
	id, ok := bindKeyID(ctx)
	if !ok {
		return
	}

	var body cryptoenginesv2.AgreeRequest
	if err := ctx.BindJSON(&body); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	peer, err := parsePeerPublicKey(body.PeerPublicKey)
	if err != nil {
		ctx.JSON(400, gin.H{"err": "peer_public_key: " + err.Error()})
		return
	}

	handle, err := r.resolveKey(ctx, id)
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}
	defer handle.Close()

	agreer, ok := handle.(cryptoenginesv2.KeyAgreementer)
	if !ok {
		opNotSupported(ctx, string(cryptoenginesv2.OpAgreeKey))
		return
	}

	goCtx := ctx.Request.Context()

	var secret []byte
	if body.Derive {
		salt, ok := decodeOptionalB64(ctx, "kdf_salt", body.KDFSalt)
		if !ok {
			return
		}
		info, ok := decodeOptionalB64(ctx, "kdf_info", body.KDFInfo)
		if !ok {
			return
		}
		secret, err = agreer.AgreeAndDerive(goCtx, peer, body.Algorithm, cryptoenginesv2.KDFParams{
			Algorithm: body.KDFAlgorithm,
			Salt:      salt,
			Info:      info,
			Length:    body.KDFLength,
		})
	} else {
		secret, err = agreer.Agree(goCtx, peer, body.Algorithm)
	}
	if err != nil {
		handleKMSV2Error(ctx, err)
		return
	}

	ctx.JSON(200, cryptoenginesv2.AgreeResponse{
		KeyID:        id,
		SharedSecret: base64.StdEncoding.EncodeToString(secret),
	})
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

// bindKeyID extracts the :id URI parameter, writing a 400 and returning false
// if it is missing.
func bindKeyID(ctx *gin.Context) (string, bool) {
	type uriP struct {
		ID string `uri:"id" binding:"required"`
	}
	var p uriP
	if err := ctx.ShouldBindUri(&p); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return "", false
	}
	return p.ID, true
}

// decodeB64 decodes a required base64 field, writing a 400 and returning false
// on failure.
func decodeB64(ctx *gin.Context, field, value string) ([]byte, bool) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		ctx.JSON(400, gin.H{"err": field + ": invalid base64: " + err.Error()})
		return nil, false
	}
	return raw, true
}

// decodeOptionalB64 decodes an optional base64 field; an empty value yields a
// nil slice with no error.
func decodeOptionalB64(ctx *gin.Context, field, value string) ([]byte, bool) {
	if value == "" {
		return nil, true
	}
	return decodeB64(ctx, field, value)
}

// opNotSupported reports that the resolved key cannot perform the operation.
func opNotSupported(ctx *gin.Context, op string) {
	ctx.JSON(400, gin.H{"err": "key does not support operation: " + op})
}

// isVerifyMismatch reports whether err represents a signature/MAC that failed
// to verify (a valid negative result) rather than an operational failure.
func isVerifyMismatch(err error) bool {
	return errors.Is(err, cryptoenginesv2.ErrVerificationFailed)
}

// hashForAlg maps a signing AlgorithmID to the crypto.Hash it implies, for use
// as crypto.SignerOpts. Ed25519 (no prehash) and unknown algorithms yield 0.
func hashForAlg(alg cryptoenginesv2.AlgorithmID) crypto.Hash {
	switch alg {
	case cryptoenginesv2.AlgRSASSAPKCS1V15SHA256, cryptoenginesv2.AlgRSASSAPSSSHA256, cryptoenginesv2.AlgECDSASHA256:
		return crypto.SHA256
	case cryptoenginesv2.AlgRSASSAPKCS1V15SHA384, cryptoenginesv2.AlgRSASSAPSSSHA384, cryptoenginesv2.AlgECDSASHA384:
		return crypto.SHA384
	case cryptoenginesv2.AlgRSASSAPKCS1V15SHA512, cryptoenginesv2.AlgRSASSAPSSSHA512, cryptoenginesv2.AlgECDSASHA512:
		return crypto.SHA512
	default:
		return 0
	}
}

// parsePeerPublicKey parses a PEM-encoded PKIX public key. EC keys are
// converted to their *ecdh.PublicKey form, which the ECDH agreement path
// expects; other key types are returned as parsed.
func parsePeerPublicKey(pemStr string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if ec, ok := pub.(*ecdsa.PublicKey); ok {
		ecdhPub, err := ec.ECDH()
		if err != nil {
			return nil, err
		}
		return ecdhPub, nil
	}
	return pub, nil
}

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
