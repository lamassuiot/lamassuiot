package pagination

import (
	"encoding/base64"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func encode(raw string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func TestDecodeRejectsMalformedFilter(t *testing.T) {
	for _, raw := range []string{"off:0;lim:10;filter:bad;", "off:0;lim:10;filter:bmFtZQ==-1-!;"} {
		bookmark := base64.RawURLEncoding.EncodeToString([]byte(raw))
		if _, err := Decode(bookmark); err == nil {
			t.Fatalf("accepted malformed filter %q", raw)
		}
	}
}

func TestNew(t *testing.T) {
	filters := []resources.FilterOption{{Field: "status", FilterOperation: resources.StringEqual, Value: "ACTIVE"}}

	cases := []struct {
		name   string
		params *resources.QueryParameters
		want   Page
	}{
		{
			name:   "nil parameters use the default page size",
			params: nil,
			want:   Page{Limit: resources.DefaultPageSize},
		},
		{
			name:   "empty parameters use the default page size",
			params: &resources.QueryParameters{},
			want:   Page{Limit: resources.DefaultPageSize},
		},
		{
			name:   "page size is kept",
			params: &resources.QueryParameters{PageSize: 10},
			want:   Page{Limit: 10},
		},
		{
			name:   "page size is capped",
			params: &resources.QueryParameters{PageSize: resources.MaxPageSize + 1},
			want:   Page{Limit: resources.MaxPageSize},
		},
		{
			name:   "negative page size uses the default",
			params: &resources.QueryParameters{PageSize: -1},
			want:   Page{Limit: resources.DefaultPageSize},
		},
		{
			name:   "sort without mode defaults to ascending",
			params: &resources.QueryParameters{Sort: resources.SortOptions{SortField: "id"}},
			want:   Page{Limit: resources.DefaultPageSize, Sort: resources.SortOptions{SortField: "id", SortMode: resources.SortModeAsc}},
		},
		{
			name:   "sort mode is kept",
			params: &resources.QueryParameters{Sort: resources.SortOptions{SortField: "id", SortMode: resources.SortModeDesc}},
			want:   Page{Limit: resources.DefaultPageSize, Sort: resources.SortOptions{SortField: "id", SortMode: resources.SortModeDesc}},
		},
		{
			name:   "sort mode without field is dropped",
			params: &resources.QueryParameters{Sort: resources.SortOptions{SortMode: resources.SortModeDesc}},
			want:   Page{Limit: resources.DefaultPageSize},
		},
		{
			name:   "filters are kept",
			params: &resources.QueryParameters{Filters: filters},
			want:   Page{Limit: resources.DefaultPageSize, Filters: filters},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := New(tc.params)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestNewDecodesBookmarkAndIgnoresOtherParameters(t *testing.T) {
	got, err := New(&resources.QueryParameters{
		NextBookmark: encode("off:20;lim:10;"),
		PageSize:     99,
		Sort:         resources.SortOptions{SortField: "id"},
	})
	require.NoError(t, err)
	assert.Equal(t, Page{Offset: 20, Limit: 10}, got)

	_, err = New(&resources.QueryParameters{NextBookmark: "!"})
	assert.Error(t, err)
}

func TestNextRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		page Page
	}{
		{
			name: "offset and limit only",
			page: Page{Offset: 0, Limit: 10},
		},
		{
			name: "sort and filters",
			page: Page{
				Offset: 10,
				Limit:  5,
				Sort:   resources.SortOptions{SortField: "created_at", SortMode: resources.SortModeDesc},
				Filters: []resources.FilterOption{
					{Field: "status", FilterOperation: resources.StringEqual, Value: "ACTIVE"},
					// Separators of the bookmark format inside field and value.
					{Field: "a-b;c:d", FilterOperation: resources.StringContains, Value: "x-y;z:w"},
				},
			},
		},
		{
			name: "sort by JSON path",
			page: Page{
				Limit: 50,
				Sort:  resources.SortOptions{SortField: "metadata", SortMode: resources.SortModeAsc, JsonPathExpr: "$.owner.name"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decode(tc.page.Next())
			require.NoError(t, err)

			want := tc.page
			want.Offset += tc.page.Limit
			assert.Equal(t, want, got)
		})
	}
}

func TestNextOmitsSortWithoutField(t *testing.T) {
	page := Page{Limit: 10, Sort: resources.SortOptions{SortMode: resources.SortModeDesc, JsonPathExpr: "$.a"}}
	assert.Equal(t, encode("off:10;lim:10;"), page.Next())
}

func TestDecode(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want Page
	}{
		{
			name: "empty bookmark uses the default page size",
			raw:  "",
			want: Page{Limit: resources.DefaultPageSize},
		},
		{
			name: "limit is capped",
			raw:  "off:0;lim:5000;",
			want: Page{Limit: resources.MaxPageSize},
		},
		{
			name: "empty and unknown parts are ignored",
			raw:  ";;off:3;unknown:1;lim:7",
			want: Page{Offset: 3, Limit: 7},
		},
		{
			name: "sort field without mode is dropped",
			raw:  "off:0;lim:10;sortB:id;",
			want: Page{Limit: 10},
		},
		{
			name: "sort mode without field is dropped",
			raw:  "off:0;lim:10;sortM:asc;",
			want: Page{Limit: 10},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decode(encode(tc.raw))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDecodeRejectsInvalidBookmarks(t *testing.T) {
	cases := map[string]string{
		"not base64":            "!",
		"padded base64":         base64.URLEncoding.EncodeToString([]byte("off:0")), // "b2ZmOjA="
		"part without colon":    encode("off:0;lim;"),
		"non-numeric offset":    encode("off:x;lim:10;"),
		"negative offset":       encode("off:-1;lim:10;"),
		"non-numeric limit":     encode("off:0;lim:x;"),
		"zero limit":            encode("off:0;lim:0;"),
		"negative limit":        encode("off:0;lim:-5;"),
		"invalid sort JSONPath": encode("off:0;lim:10;sortM:asc;sortB:id;sortJP:!;"),
		"non-numeric operator":  encode("off:0;lim:10;filter:bmFtZQ==-x-dmFsdWU=;"),
		"invalid filter field":  encode("off:0;lim:10;filter:!-1-dmFsdWU=;"),
		"filter with 4 parts":   encode("off:0;lim:10;filter:bmFtZQ==-1-dmFsdWU=-x;"),
	}
	for name, bookmark := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(bookmark)
			assert.EqualError(t, err, "not a valid bookmark")
		})
	}
}
