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

// ApplyPatches applies patches to the provided metadata and returns the updated metadata or an error.
// It automatically creates parent arrays when adding elements to non-existing array paths.
func ApplyPatches[rt any](metadata any, patches []models.PatchOperation) (*rt, error) {
	opts := jsonpatch.NewApplyOptions()
	opts.AllowMissingPathOnRemove = true
	opts.EnsurePathExistsOnAdd = true

	// Marshal the metadata to JSON bytes
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %v", err)
	}

	// Pre-process patches to ensure parent arrays exist when adding to array indices
	enhancedPatches, err := ensureArrayParentsExist(patches, metadataBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to pre-process patches: %w", err)
	}

	// Convert custom Patch struct to JSON Patch format
	patchBytes, err := json.Marshal(enhancedPatches)
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
	var updatedMetadata rt
	err = json.Unmarshal(res, &updatedMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal updated metadata: %v", err)
	}

	return &updatedMetadata, nil
}

// ensureArrayParentsExist pre-processes patches to create parent arrays when adding to array indices
func ensureArrayParentsExist(patches []models.PatchOperation, metadataBytes []byte) ([]models.PatchOperation, error) {
	var metadata map[string]interface{}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		// If it's not a map, return patches as-is
		return patches, nil
	}

	enhancedPatches := make([]models.PatchOperation, 0, len(patches)*2)
	createdPaths := make(map[string]bool)

	for _, patch := range patches {
		// Only process "add" operations
		if patch.Op != models.PatchAdd {
			enhancedPatches = append(enhancedPatches, patch)
			continue
		}

		// Check if path points to an array element (ends with /number or /-)
		if parentPath := getArrayParentPath(patch.Path); parentPath != "" {
			// Check if parent array exists
			if !pathExists(metadata, parentPath) && !createdPaths[parentPath] {
				// Create the parent array first
				enhancedPatches = append(enhancedPatches, models.PatchOperation{
					Op:    models.PatchAdd,
					Path:  parentPath,
					Value: []interface{}{},
				})
				createdPaths[parentPath] = true
			}
		}

		enhancedPatches = append(enhancedPatches, patch)
	}

	return enhancedPatches, nil
}

// getArrayParentPath extracts the parent path if the path ends with an array index
func getArrayParentPath(path string) string {
	if path == "" || path == "/" {
		return ""
	}

	// Find the last slash
	lastSlash := strings.LastIndex(path, "/")
	if lastSlash <= 0 {
		return ""
	}

	// Get the last segment
	lastSegment := path[lastSlash+1:]

	// Check if it's an array index (number or "-")
	if lastSegment == "-" || isNumeric(lastSegment) {
		return path[:lastSlash]
	}

	return ""
}

// isNumeric checks if a string is a valid array index
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// pathExists checks if a path exists in the metadata
func pathExists(metadata map[string]interface{}, path string) bool {
	if path == "" || path == "/" {
		return true
	}

	// Remove leading slash
	path = strings.TrimPrefix(path, "/")

	// Split path and decode RFC 6901 encoding
	segments := strings.Split(path, "/")
	current := interface{}(metadata)

	for _, segment := range segments {
		// Decode the segment
		decodedSegment := decodePathSegment(segment)

		switch v := current.(type) {
		case map[string]interface{}:
			val, exists := v[decodedSegment]
			if !exists {
				return false
			}
			current = val
		case []interface{}:
			// For arrays, we just check if the array exists, not the specific index
			return true
		default:
			return false
		}
	}

	return true
}

// decodePathSegment decodes RFC 6901 JSON Pointer encoding
func decodePathSegment(segment string) string {
	// Reverse of encodePatchKey: ~1 -> /, ~0 -> ~
	s := strings.ReplaceAll(segment, "~1", "/")
	s = strings.ReplaceAll(s, "~0", "~")
	return s
}
