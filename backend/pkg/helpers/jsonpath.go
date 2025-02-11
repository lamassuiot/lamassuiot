package helpers

import (
	"github.com/spyzhov/ajson"
)

func JsonPathExists(data []byte, path string) (bool, error) {
	ajsonData, err := ajson.JSONPath(data, path)
	if err != nil {
		return false, err
	}

	return len(ajsonData) > 0, nil
}
