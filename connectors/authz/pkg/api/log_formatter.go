package api

import (
	"bytes"
	"encoding/json"
	"sort"
	"time"

	"github.com/sirupsen/logrus"
)

// authzFieldOrder defines the JSON key sequence for authz log lines.
// Fields not listed here appear after, sorted alphabetically.
var authzFieldOrder = []string{
	"service", "subsystem",
	"trace-id", "span-id",
	"src", "auth-type", "auth-id",
	"principal_id", "auth_type",
	"namespace", "schema", "entity_type", "action",
	"allowed", "reason",
	"matched_count", "condition_count", "join_count",
	"policy_id",
	"where_clause", "filter_sql",
	"error",
}

// OrderedJSONFormatter emits one JSON object per log entry with a stable field order.
// Fields in FieldOrder appear first; any remaining data fields follow alphabetically.
type OrderedJSONFormatter struct {
	TimestampFormat string
	FieldOrder      []string
}

func (f *OrderedJSONFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	tsFormat := f.TimestampFormat
	if tsFormat == "" {
		tsFormat = time.RFC3339Nano
	}

	buf := &bytes.Buffer{}
	buf.WriteByte('{')

	first := true
	write := func(key string, val interface{}) {
		if !first {
			buf.WriteByte(',')
		}
		first = false
		k, _ := json.Marshal(key)
		v, _ := json.Marshal(val)
		buf.Write(k)
		buf.WriteByte(':')
		buf.Write(v)
	}

	// Fixed prefix: timestamp, level, message.
	write("time", entry.Time.Format(tsFormat))
	write("level", entry.Level.String())
	write("msg", entry.Message)

	// Declared fields in order.
	seen := make(map[string]bool, len(f.FieldOrder))
	for _, key := range f.FieldOrder {
		if v, ok := entry.Data[key]; ok {
			write(key, v)
			seen[key] = true
		}
	}

	// Remaining data fields alphabetically.
	remaining := make([]string, 0, len(entry.Data))
	for k := range entry.Data {
		if !seen[k] {
			remaining = append(remaining, k)
		}
	}
	sort.Strings(remaining)
	for _, k := range remaining {
		write(k, entry.Data[k])
	}

	buf.WriteByte('}')
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}
