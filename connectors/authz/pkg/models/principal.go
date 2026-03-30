package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// Principal represents an abstraction of a user in the authorization system
type Principal struct {
	ID          string     `gorm:"primaryKey;size:255" json:"id"`
	Name        string     `gorm:"size:255;not null" json:"name"`
	Description string     `gorm:"size:1024" json:"description,omitempty"`
	Type        string     `gorm:"size:50;not null;index" json:"type"` // "oidc", "x509"
	AuthConfig  AuthConfig `gorm:"type:jsonb" json:"authConfig"`
	Active      bool       `gorm:"default:true;not null" json:"active"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`

	// Many-to-many relationship with policies
	Policies []PrincipalPolicy `gorm:"foreignKey:PrincipalID" json:"-"`
}

// AuthConfig stores type-specific authentication configuration
type AuthConfig map[string]interface{}

// Value implements the driver.Valuer interface for GORM
func (a AuthConfig) Value() (driver.Value, error) {
	return json.Marshal(a)
}

// Scan implements the sql.Scanner interface for GORM
func (a *AuthConfig) Scan(value interface{}) error {
	if value == nil {
		*a = make(AuthConfig)
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to unmarshal AuthConfig value: %v", value)
	}

	return json.Unmarshal(bytes, a)
}

// PrincipalPolicy represents the many-to-many association between principals and policies
type PrincipalPolicy struct {
	ID          uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	PrincipalID string    `gorm:"size:255;not null;index:idx_principal_policy,unique" json:"principalId"`
	PolicyID    string    `gorm:"size:255;not null;index:idx_principal_policy,unique" json:"policyId"`
	GrantedAt   time.Time `gorm:"autoCreateTime" json:"grantedAt"`
	GrantedBy   string    `gorm:"size:255" json:"grantedBy,omitempty"`

	// Foreign key relationships
	Principal Principal `gorm:"foreignKey:PrincipalID;references:ID" json:"-"`
}

// TableName specifies the table name for Principal
func (Principal) TableName() string {
	return "principals"
}

// TableName specifies the table name for PrincipalPolicy
func (PrincipalPolicy) TableName() string {
	return "principal_policies"
}
