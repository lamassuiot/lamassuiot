package query

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/stretchr/testify/require"
)

var testFields = map[string]resources.FilterFieldType{
	"name": resources.StringFilterFieldType, "tags": resources.StringArrayFilterFieldType,
	"created": resources.DateFilterFieldType, "count": resources.NumberFilterFieldType,
	"status": resources.EnumFilterFieldType, "metadata": resources.JsonFilterFieldType,
}

func TestFilterQueryParsesSortPagingAndFilters(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?sort_by=metadata%5Bjsonpath%5D%24.name&sort_mode=desc&page_size=9999&bookmark=next&filter=name%5Beq%5Dfoo&filter=metadata%5Bjsonpath%5D%24.x%2520%3D%3D%2520%22y%22", nil)
	got, err := FilterQuery(req, testFields)
	require.NoError(t, err)
	require.Equal(t, resources.MaxPageSize, got.PageSize)
	require.Equal(t, "next", got.NextBookmark)
	require.Equal(t, resources.SortModeDesc, got.Sort.SortMode)
	require.Equal(t, "metadata", got.Sort.SortField)
	require.Len(t, got.Filters, 2)
}

func TestFilterQueryRejectsUnknownOperand(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?filter=name%5Bunknown%5Dx", nil)
	_, err := FilterQuery(req, testFields)
	require.Error(t, err)
}

func TestParseFilterOperands(t *testing.T) {
	tests := []struct {
		fieldType resources.FilterFieldType
		operands  []string
	}{
		{resources.StringFilterFieldType, []string{"eq", "eq_ic", "ne", "ne_ic", "ct", "ct_ic", "nc", "nc_ic", "in", "in_ic", "nin", "nin_ic"}},
		{resources.StringArrayFilterFieldType, []string{"ct", "ct_ic"}},
		{resources.DateFilterFieldType, []string{"bf", "eq", "af"}},
		{resources.NumberFilterFieldType, []string{"eq", "ne", "lt", "le", "gt", "ge"}},
		{resources.EnumFilterFieldType, []string{"eq", "ne", "in"}},
		{resources.JsonFilterFieldType, []string{"jsonpath"}},
	}
	for _, test := range tests {
		for _, operand := range test.operands {
			require.NotEqual(t, resources.UnspecifiedFilter, parseFilterOperand(operand, test.fieldType))
		}
	}
	require.Equal(t, resources.UnspecifiedFilter, parseFilterOperand("unknown", resources.StringFilterFieldType))
}

func TestJSONPathValidation(t *testing.T) {
	require.True(t, isValidJsonPath(`$.items[*] ? (@.name == "value")`))
	for _, path := range []string{"", "items", "$.a]", "$.a[", "$.a(", "$.a)", "$.a;drop", "$.a...", "$.a===", "$.a&&&", "$.a|||", "$.a💥", strings.Repeat("a", 501)} {
		require.False(t, isValidJsonPath(path), path)
	}
}

func TestFilterQueryIgnoresInvalidSortAndMalformedFilters(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?sort_by=metadata%5Bjsonpath%5D%24.a%3Bdrop&filter=malformed", nil)
	got, err := FilterQuery(req, testFields)
	require.NoError(t, err)
	require.Empty(t, got.Sort.SortField)
	require.Empty(t, got.Filters)
}

func TestFilterQueryWithPrefix(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?ca_filter=status%5Beq%5Dactive", nil)
	got, err := FilterQueryWithPrefix(req, testFields, "ca_filter")
	require.NoError(t, err)
	require.Len(t, got.Filters, 1)
	require.Equal(t, "status", got.Filters[0].Field)
	require.Nil(t, mustPrefix(http.MethodGet, "/?filter=x", "missing"))
}

func mustPrefix(method, target, prefix string) *resources.QueryParameters {
	got, _ := FilterQueryWithPrefix(httptest.NewRequest(method, target, nil), testFields, prefix)
	return got
}

func TestConvertDeviceGroupCriteriaAndResponse(t *testing.T) {
	criteria := []resources.DeviceGroupFilterOptionRequest{{Field: "status", Operand: "eq", Value: "ACTIVE"}}
	got, err := ConvertDeviceGroupCriteria(criteria, testFields)
	require.NoError(t, err)
	require.Len(t, got, 1)
	_, err = ConvertDeviceGroupCriteria([]resources.DeviceGroupFilterOptionRequest{{Field: "missing", Operand: "eq"}}, testFields)
	require.Error(t, err)
	_, err = ConvertDeviceGroupCriteria([]resources.DeviceGroupFilterOptionRequest{{Field: "status", Operand: "bad"}}, testFields)
	require.Error(t, err)

	require.Nil(t, ConvertDeviceGroupToResponse(nil, 0))
	parent := "root"
	response := ConvertDeviceGroupToResponse(&models.DeviceGroup{
		ID: "g1", Name: "group", ParentID: &parent,
		Criteria: []models.DeviceGroupFilterOption{{Field: "status", FilterOperation: int(resources.EnumEqual), Value: "ACTIVE"}},
	}, 0)
	require.Equal(t, "root", response["parent_id"])
	require.Len(t, response["inherited_criteria"], 1)
}
