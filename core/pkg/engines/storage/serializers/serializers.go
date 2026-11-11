// Package serializers contains GORM serializers shared by storage providers.
package serializers

import (
	"context"
	"encoding"
	"fmt"
	"reflect"
	"sync"

	"gorm.io/gorm/schema"
)

var registerOnce sync.Once

// Register installs the serializers before parsing storage models.
func Register() {
	registerOnce.Do(func() {
		schema.RegisterSerializer("text", TextSerializer{})
		schema.RegisterSerializer("nullstring", NullStringSerializer{})
	})
}

// NullStringSerializer stores the empty string as NULL. It is for the columns of a foreign key, which
// does not check a NULL: the empty string would have to reference a row that does not exist.
type NullStringSerializer struct{}

func (NullStringSerializer) Scan(ctx context.Context, field *schema.Field, dst reflect.Value, dbValue any) error {
	var value string
	switch v := dbValue.(type) {
	case nil:
	case string:
		value = v
	case []byte:
		value = string(v)
	default:
		return fmt.Errorf("unsupported dbValue type: %T", dbValue)
	}

	field.ReflectValueOf(ctx, dst).SetString(value)
	return nil
}

func (NullStringSerializer) Value(ctx context.Context, field *schema.Field, dst reflect.Value, fieldValue any) (any, error) {
	if value, _ := fieldValue.(string); value != "" {
		return value, nil
	}
	return nil, nil
}

// TextSerializer string serializer
type TextSerializer struct{}

func (TextSerializer) Scan(ctx context.Context, field *schema.Field, dst reflect.Value, dbValue any) (err error) {
	// Create a new instance of the field type
	fieldValue := reflect.New(field.FieldType).Interface()

	// Check if the fieldValue implements encoding.TextUnmarshaler
	unmarshaler, ok := fieldValue.(encoding.TextUnmarshaler)
	if !ok {
		return fmt.Errorf("field type does not implement encoding.TextUnmarshaler")
	}

	// Convert dbValue to a string or []byte
	var textData []byte
	switch v := dbValue.(type) {
	case string:
		textData = []byte(v)
	case []byte:
		textData = v
	default:
		return fmt.Errorf("unsupported dbValue type: %T", dbValue)
	}

	// Use the UnmarshalText method to populate the field
	if err := unmarshaler.UnmarshalText(textData); err != nil {
		return fmt.Errorf("failed to unmarshal text: %w", err)
	}

	// Set the value back to the destination
	field.ReflectValueOf(ctx, dst).Set(reflect.ValueOf(fieldValue).Elem())
	return nil
}

// Value implements serializer interface
func (TextSerializer) Value(ctx context.Context, field *schema.Field, dst reflect.Value, fieldValue any) (any, error) {
	// Check if fieldValue implements encoding.TextMarshaler
	if marshaler, ok := fieldValue.(encoding.TextMarshaler); ok {
		text, err := marshaler.MarshalText()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal text: %w", err)
		}
		return string(text), nil // Return the text representation as a string
	}

	return nil, fmt.Errorf("fieldValue does not implement encoding.TextMarshaler")
}
