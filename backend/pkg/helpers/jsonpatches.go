package helpers

import (
	"encoding/json"
	"fmt"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

// ApplyPatches applies patches to the provided metadata and returns the updated metadata or an error
func ApplyPatches(metadata map[string]interface{}, patches models.Patch) (map[string]interface{}, error) {
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
