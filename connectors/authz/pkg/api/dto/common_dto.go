package dto

// ErrorResponse represents an API error
type ErrorResponse struct {
	Error   string            `json:"error"`
	Code    string            `json:"code,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}

// SuccessResponse represents a successful response
type SuccessResponse struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// PaginationRequest for list endpoints
type PaginationRequest struct {
	Page     int `form:"page" binding:"min=1"`
	PageSize int `form:"pageSize" binding:"min=1,max=100"`
}

// PaginationResponse metadata
type PaginationResponse struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"pageSize"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"totalPages"`
}
