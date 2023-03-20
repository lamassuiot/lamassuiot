package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/lamassuiot/lamassuiot/pkg/resources"
)

func Post[T any](ctx context.Context, url string, data any) (T, error) {
	var m T
	b, err := toJSON(data)
	if err != nil {
		return m, err
	}

	byteReader := bytes.NewReader(b)
	r, err := http.NewRequestWithContext(ctx, "POST", url, byteReader)
	if err != nil {
		return m, err
	}
	// Important to set
	r.Header.Add("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		return m, err
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return m, err
	}

	if res.StatusCode != 200 && res.StatusCode != 201 {
		return m, fmt.Errorf("unexpected status code %d. Body msg: %s", res.StatusCode, string(body))
	}

	return parseJSON[T](body)
}

func Get[T any](ctx context.Context, url string, queryParams *resources.QueryParameters) (T, error) {
	var m T

	r, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return m, err
	}

	if queryParams != nil {
		if queryParams.Pagination.NextBookmark != "" {
			query := r.URL.Query()
			query.Add("bookmark", queryParams.Pagination.NextBookmark)
			r.URL.RawQuery = query.Encode()
		}
	}
	// Important to set
	r.Header.Add("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		return m, err
	}

	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return m, err
	}

	if res.StatusCode != 200 {
		return m, fmt.Errorf("unexpected status code %d. Body msg: %s", res.StatusCode, string(body))
	}

	return parseJSON[T](body)
}

func IterGet[E any, T resources.Iterator[E]](ctx context.Context, url string, queryParams *resources.QueryParameters, applyFunc func(*E)) error {
	continueIter := true
	if queryParams == nil {
		queryParams = &resources.QueryParameters{}
	}

	queryParams.Pagination.NextBookmark = ""

	for continueIter {
		response, err := Get[T](context.Background(), url, queryParams)
		if err != nil {
			return err
		}

		if response.GetNextBookmark() == "" {
			continueIter = false
		} else {
			queryParams.Pagination.NextBookmark = response.GetNextBookmark()
		}

		for _, item := range response.GetList() {
			if item != nil {
				applyFunc(item)
			}
		}
	}

	return nil
}

func parseJSON[T any](s []byte) (T, error) {
	var r T
	if err := json.Unmarshal(s, &r); err != nil {
		return r, err
	}
	return r, nil
}

func toJSON(T any) ([]byte, error) {
	return json.Marshal(T)
}
