package serializers

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm/schema"
)

// upper is stored as lower case text and read back in upper case.
type upper string

func (u upper) MarshalText() ([]byte, error) {
	if u == "FAIL" {
		return nil, errors.New("cannot marshal")
	}
	return []byte(strings.ToLower(string(u))), nil
}

func (u *upper) UnmarshalText(text []byte) error {
	if string(text) == "fail" {
		return errors.New("cannot unmarshal")
	}
	*u = upper(strings.ToUpper(string(text)))
	return nil
}

type row struct {
	ID     string
	Text   upper  `gorm:"serializer:text"`
	Plain  int    `gorm:"serializer:text"`
	Parent string `gorm:"serializer:nullstring"`
}

func parseField(t *testing.T, name string) *schema.Field {
	t.Helper()
	Register()
	s, err := schema.Parse(&row{}, &sync.Map{}, schema.NamingStrategy{})
	require.NoError(t, err)
	field := s.LookUpField(name)
	require.NotNil(t, field, "field %s", name)
	return field
}

func TestRegisterInstallsSerializers(t *testing.T) {
	Register()
	Register() // idempotent

	text, ok := schema.GetSerializer("text")
	require.True(t, ok)
	assert.IsType(t, TextSerializer{}, text)

	nullString, ok := schema.GetSerializer("nullstring")
	require.True(t, ok)
	assert.IsType(t, NullStringSerializer{}, nullString)
}

func TestNullStringSerializerScan(t *testing.T) {
	field := parseField(t, "Parent")
	ctx := context.Background()

	cases := []struct {
		name    string
		dbValue any
		want    string
	}{
		{"nil becomes empty string", nil, ""},
		{"string", "parent-1", "parent-1"},
		{"bytes", []byte("parent-2"), "parent-2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := row{Parent: "previous"}
			err := NullStringSerializer{}.Scan(ctx, field, reflect.ValueOf(&r).Elem(), tc.dbValue)
			require.NoError(t, err)
			assert.Equal(t, tc.want, r.Parent)
		})
	}

	t.Run("unsupported type", func(t *testing.T) {
		r := row{Parent: "previous"}
		err := NullStringSerializer{}.Scan(ctx, field, reflect.ValueOf(&r).Elem(), 42)
		assert.ErrorContains(t, err, "unsupported dbValue type: int")
		assert.Equal(t, "previous", r.Parent)
	})
}

func TestNullStringSerializerValue(t *testing.T) {
	field := parseField(t, "Parent")
	ctx := context.Background()

	cases := []struct {
		name       string
		fieldValue any
		want       any
	}{
		{"non-empty string is kept", "parent-1", "parent-1"},
		{"empty string becomes NULL", "", nil},
		{"non-string becomes NULL", 42, nil},
		{"nil becomes NULL", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NullStringSerializer{}.Value(ctx, field, reflect.Value{}, tc.fieldValue)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestTextSerializerScan(t *testing.T) {
	field := parseField(t, "Text")
	ctx := context.Background()

	for name, dbValue := range map[string]any{"string": "value", "bytes": []byte("value")} {
		t.Run(name, func(t *testing.T) {
			var r row
			err := TextSerializer{}.Scan(ctx, field, reflect.ValueOf(&r).Elem(), dbValue)
			require.NoError(t, err)
			assert.Equal(t, upper("VALUE"), r.Text)
		})
	}

	t.Run("unsupported type", func(t *testing.T) {
		var r row
		err := TextSerializer{}.Scan(ctx, field, reflect.ValueOf(&r).Elem(), 42)
		assert.ErrorContains(t, err, "unsupported dbValue type: int")
	})

	t.Run("unmarshal error", func(t *testing.T) {
		var r row
		err := TextSerializer{}.Scan(ctx, field, reflect.ValueOf(&r).Elem(), "fail")
		assert.ErrorContains(t, err, "failed to unmarshal text: cannot unmarshal")
		assert.Empty(t, r.Text)
	})

	t.Run("field type without TextUnmarshaler", func(t *testing.T) {
		var r row
		err := TextSerializer{}.Scan(ctx, parseField(t, "Plain"), reflect.ValueOf(&r).Elem(), "1")
		assert.ErrorContains(t, err, "does not implement encoding.TextUnmarshaler")
	})
}

func TestTextSerializerValue(t *testing.T) {
	field := parseField(t, "Text")
	ctx := context.Background()

	got, err := TextSerializer{}.Value(ctx, field, reflect.Value{}, upper("VALUE"))
	require.NoError(t, err)
	assert.Equal(t, "value", got)

	_, err = TextSerializer{}.Value(ctx, field, reflect.Value{}, upper("FAIL"))
	assert.ErrorContains(t, err, "failed to marshal text: cannot marshal")

	_, err = TextSerializer{}.Value(ctx, field, reflect.Value{}, 42)
	assert.ErrorContains(t, err, "does not implement encoding.TextMarshaler")
}
