package models

type PatchOp string

const (
	PatchAdd     PatchOp = "add"
	PatchRemove  PatchOp = "remove"
	PatchReplace PatchOp = "replace"
)

// PatchOperation represents a single JSON Patch operation.
type PatchOperation struct {
	Op    PatchOp     `json:"op"`              // "add", "remove", "replace"
	Path  string      `json:"path"`            // JSON Pointer to the target field
	Value interface{} `json:"value,omitempty"` // New value (for "add", "replace")
}
