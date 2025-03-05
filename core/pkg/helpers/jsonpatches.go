package helpers

import (
	"encoding/json"
	"fmt"
	"strings"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

/* ------------------------ JSON Pointer Utilities ------------------------ */

type JSONPointer struct {
	Pointer string
}

// JSONPointerBuilder constructs a JSON Pointer string from a sequence of path segments.
func JSONPointerBuilder(p ...string) JSONPointer {
	var sb strings.Builder
	for _, token := range p {
		sb.WriteByte('/')
		sb.WriteString(encodePatchKey(token))
	}
	return JSONPointer{Pointer: sb.String()}
}

// Encode JSON Pointer key
func encodePatchKey(k string) string {
	// Replacer to encode JSON Pointer escaping (RFC 6901)
	var rfc6901Encoder = strings.NewReplacer("~", "~0", "/", "~1")
	return rfc6901Encoder.Replace(k)
}

/* ------------------------ PatchBuilder ------------------------ */

type PatchBuilder struct {
	patches []models.PatchOperation
}

func NewPatchBuilder() *PatchBuilder {
	return &PatchBuilder{}
}

func (pb *PatchBuilder) addOperation(op models.PatchOp, path JSONPointer, value interface{}) *PatchBuilder {
	pb.patches = append(pb.patches, models.PatchOperation{
		Op:    op,
		Path:  path.Pointer,
		Value: value,
	})
	return pb
}

func (pb *PatchBuilder) Add(path JSONPointer, value interface{}) *PatchBuilder {
	return pb.addOperation(models.PatchAdd, path, value)
}

func (pb *PatchBuilder) Replace(path JSONPointer, value interface{}) *PatchBuilder {
	return pb.addOperation(models.PatchReplace, path, value)
}

func (pb *PatchBuilder) Remove(path JSONPointer) *PatchBuilder {
	return pb.addOperation(models.PatchRemove, path, nil)
}

func (pb *PatchBuilder) Build() []models.PatchOperation {
	return pb.patches
}

/* ------------------------ Patch Application ------------------------ */

// ApplyPatches applies patches to the provided metadata and returns the updated metadata or an error
func ApplyPatches(metadata map[string]interface{}, patches []models.PatchOperation) (map[string]interface{}, error) {
	opts := jsonpatch.NewApplyOptions()
	opts.AllowMissingPathOnRemove = true
	opts.EnsurePathExistsOnAdd = true

	// Marshal the metadata to JSON bytes
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %v", err)
	}

	// Convert custom Patch struct to JSON Patch format
	patchBytes, err := json.Marshal(patches)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal patches: %w", err)
	}

	// Decode the JSON Patch
	patch, err := jsonpatch.DecodePatch(patchBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode patches: %w", err)
	}

	// Apply the patches
	res, err := patch.ApplyWithOptions(metadataBytes, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to apply patches to metadata: %v", err)
	}

	// Unmarshal the result back into a map
	var updatedMetadata map[string]interface{}
	err = json.Unmarshal(res, &updatedMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal updated metadata: %v", err)
	}

	return updatedMetadata, nil
}
