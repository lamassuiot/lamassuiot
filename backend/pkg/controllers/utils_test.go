package controllers

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

func TestFilterQuery_SubjectKeyID(t *testing.T) {
	req := &http.Request{}
	req.URL = &url.URL{}
	q := req.URL.Query()
	q.Add("filter", "subject_key_id[eq]ABC123")
	req.URL.RawQuery = q.Encode()

	qp := FilterQuery(req, resources.CertificateFilterableFields)
	if qp == nil {
		t.Fatalf("expected QueryParameters, got nil")
	}

	if len(qp.Filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(qp.Filters))
	}

	f := qp.Filters[0]
	if f.Field != "subject_key_id" {
		t.Fatalf("expected field 'subject_key_id', got '%s'", f.Field)
	}
	if f.Value != "ABC123" {
		t.Fatalf("expected value 'ABC123', got '%s'", f.Value)
	}
	if f.FilterOperation != resources.StringEqual {
		t.Fatalf("expected operation StringEqual, got %v", f.FilterOperation)
	}
}
