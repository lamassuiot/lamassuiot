//go:build experimental
// +build experimental

package couchdb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	_ "github.com/go-kivik/couchdb" // The CouchDB driver
	"github.com/go-kivik/couchdb/v4"
	"github.com/go-kivik/couchdb/v4/chttp"
	"github.com/go-kivik/kivik/v4"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/sirupsen/logrus"
)

var (
	lCouch *logrus.Entry
)

func CreateCouchDBConnection(logger *logrus.Entry, cfg config.CouchDBPSEConfig) (*kivik.Client, error) {
	address := fmt.Sprintf("%s://%s:%s@%s:%d%s", cfg.Protocol, cfg.Username, cfg.Password, cfg.Hostname, cfg.Port, cfg.BasePath)
	httpCli, err := helpers.BuildHTTPClientWithTLSOptions(&http.Client{}, cfg.TLSConfig)
	if err != nil {
		return nil, err
	}

	lCouch = logger.WithField("subsystem-provider", "CouchDB")
	httpCli, err = helpers.BuildHTTPClientWithTracerLogger(httpCli, lCouch)
	if err != nil {
		return nil, err
	}

	kivikOpts := kivik.Options{
		couchdb.OptionHTTPClient: httpCli,
	}

	client, err := kivik.New("couch", address, kivikOpts)
	if err != nil {
		return nil, err
	}

	ping, err := client.Ping(context.Background())
	if err != nil {
		return nil, err
	}

	if !ping {
		return nil, fmt.Errorf("no connectivity with couchdb")
	}

	return client, nil
}

func CheckAndCreateDB(client *kivik.Client, db string) error {
	if exists, err := client.DBExists(context.TODO(), db); err == nil && !exists {
		lCouch.Infof("db does not exist. Creating db: %s", db)
		if err := client.CreateDB(context.TODO(), db); err != nil {
			lCouch.Error(fmt.Sprintf("could not create db %s: %s", db, err))
			return err
		}
	}

	return nil
}

type couchDBQuerier[E any] struct {
	*kivik.DB
}

func newCouchDBQuerier[E any](db *kivik.DB) couchDBQuerier[E] {
	return couchDBQuerier[E]{
		DB: db,
	}
}

func (db *couchDBQuerier[E]) CreateBasicCounterView() error {
	querier := newCouchDBQuerier[map[string]interface{}](db.DB)
	_, err := querier.DB.Put(context.TODO(), "_design/utils", map[string]interface{}{
		"_id": "_design/utils",
		"views": map[string]interface{}{
			"count": map[string]interface{}{
				"map":    "function(doc) { emit(doc._id) }",
				"reduce": "_count",
			},
		},
	})

	if err != nil {
		return fmt.Errorf("error while creating design doc: %s", err)
	}

	return nil
}

func (db *couchDBQuerier[E]) CreateIndex(fields string) error {
	querier := newCouchDBQuerier[map[string]interface{}](db.DB)

	indexPayload := map[string]interface{}{
		"language": "query",
		"views": map[string]interface{}{
			fields + "-json-index": map[string]interface{}{
				"map": map[string]interface{}{
					"fields": map[string]string{
						fields: "asc",
					},
					"partial_filter_selector": map[string]interface{}{},
				},
				"reduce": "_count",
				"options": map[string]interface{}{
					"def": map[string]interface{}{
						"fields": []string{fields},
					},
				},
			},
		},
	}

	_, err := querier.DB.Put(context.TODO(), "_design/"+fields, indexPayload)
	if err != nil {
		return fmt.Errorf("error creating index: %s", err)
	}

	return nil
}

func (db *couchDBQuerier[E]) Count(opts *map[string]interface{}) (int, error) {

	if opts == nil {
		countRows := db.AllDocs(context.Background(), map[string]interface{}{"include_docs": false})

		docCount := 0
		for countRows.Next() {
			if !strings.HasPrefix(countRows.ID(), "_design/") {
				docCount++
			}
		}
		if countRows.Err() != nil {
			return -1, fmt.Errorf("error while iterating documents: %s", countRows.Err())
		}
		defer func() {
			countRows.Close()
		}()

		return docCount, nil
	} else {
		countRowsBy := db.Find(context.Background(), opts)

		docCountEngineCA := 0
		for countRowsBy.Next() {
			docCountEngineCA++
		}

		if countRowsBy.Err() != nil {
			return -1, fmt.Errorf("error while iterating through the documents: %s", countRowsBy.Err())
		}

		defer func() {
			countRowsBy.Close()
		}()

		return docCountEngineCA, nil
	}
}

func (db *couchDBQuerier[E]) SelectAll(queryParams *resources.QueryParameters, extraOpts *map[string]interface{}, exhaustiveRun bool, applyFunc func(elem E)) (string, error) {
	nextBookmark := ""
	opts := map[string]interface{}{
		"selector": map[string]interface{}{"_id": map[string]string{"$ne": ""}},
	}

	if queryParams != nil {
		if len(queryParams.Filters) > 0 {
			for _, filter := range queryParams.Filters {
				filterSelector := FilterOperandToCouchDBSelector(filter)
				for key, value := range filterSelector {
					opts["selector"].(map[string]interface{})[key] = value
				}
			}
		}

		if queryParams.Sort.SortField != "" {
			db.ensureIndexExists(queryParams.Sort.SortField)
			opts["sort"] = []map[string]string{{queryParams.Sort.SortField: string(queryParams.Sort.SortMode)}}
		}

		if queryParams.NextBookmark != "" {
			nextBookmark = queryParams.NextBookmark
		}

		if queryParams.PageSize > 0 {
			opts["limit"] = queryParams.PageSize
		}
	}

	derefExtraOpts := *extraOpts
	if _, extraHasSelector := derefExtraOpts["selector"]; extraHasSelector {
		if extraSelectors, ok := derefExtraOpts["selector"].(map[string]interface{}); ok {
			for key, val := range extraSelectors {
				opts["selector"].(map[string]interface{})[key] = val
			}
		}
	}

	iterCounter := 0
	continueIter := true
	for continueIter {
		bookmark, elems, err := getElements[*E](db.DB, nextBookmark, opts)
		if err != nil {
			return "", err
		}

		for _, elem := range elems {
			applyFunc(*elem)
		}

		if !exhaustiveRun {
			continueIter = false
		}

		if bookmark != "nil" && bookmark != nextBookmark {
			nextBookmark = bookmark
		} else {
			nextBookmark = ""
			continueIter = false
		}

		iterCounter++
	}

	return nextBookmark, nil
}

func (db *couchDBQuerier[E]) ensureIndexExists(field string) {
	exists, _, err := db.SelectExists("_design/" + field)
	if err != nil {
		fmt.Printf("Error checking for index existence: %s\n", err)
	}
	if !exists {
		db.CreateIndex(field)
	}
}

func (db *couchDBQuerier[E]) SelectExists(elemID string) (bool, *E, error) {
	rs := db.Get(context.Background(), elemID)
	err := rs.Err()
	if err != nil {
		switch err := err.(type) {
		case *chttp.HTTPError:
			if err.Response.StatusCode == http.StatusNotFound {
				return false, nil, nil
			} else {
				return false, nil, err
			}
		default:
			return false, nil, err
		}
	}

	rs.Next()
	var elem E
	if err := rs.ScanDoc(&elem); err != nil {
		return false, nil, err
	}

	return true, &elem, nil
}

func (db *couchDBQuerier[E]) Insert(elem E, elemID string) (*E, error) {
	_, err := db.Put(context.Background(), elemID, elem)
	if err != nil {
		return nil, err
	}

	_, newElem, err := db.SelectExists(elemID)
	return newElem, err
}

func (db *couchDBQuerier[E]) Update(elem E, elemID string) (*E, error) {
	rs := db.Get(context.Background(), elemID)
	if rs.Err() != nil {
		return nil, rs.Err()
	}

	rs.Next()
	var prevElem map[string]interface{}
	if err := rs.ScanDoc(&prevElem); err != nil {
		return nil, err
	}

	marshalElem, err := json.Marshal(elem)
	if err != nil {
		return nil, err
	}

	var newElem map[string]interface{}
	err = json.Unmarshal(marshalElem, &newElem)
	if err != nil {
		return nil, err
	}

	newElem["_rev"] = prevElem["_rev"]
	_, err = db.Put(context.Background(), elemID, newElem)
	if err != nil {
		return nil, err
	}

	_, newUpdatedElem, err := db.SelectExists(elemID)
	return newUpdatedElem, err
}

func (db *couchDBQuerier[E]) Delete(elemID string) error {
	rs := db.Get(context.Background(), elemID)
	if rs.Err() != nil {
		return rs.Err()
	}

	rs.Next()
	var prevElem map[string]interface{}
	if err := rs.ScanDoc(&prevElem); err != nil {
		return err
	}

	_, err := db.DB.Delete(context.Background(), elemID, prevElem["_rev"].(string))
	if err != nil {
		return err
	}

	return err
}

func getElements[E any](db *kivik.DB, bookmark string, opts map[string]interface{}) (string, []E, error) {
	ctx := context.Background()

	if bookmark != "" {
		opts["bookmark"] = bookmark
	}

	rs := db.Find(ctx, opts)
	if rs.Err() != nil {
		return "", []E{}, rs.Err()
	}

	elements := []E{}

	for rs.Next() {
		var element E
		if err := rs.ScanDoc(&element); err != nil {
			lCouch.Warnf("error while processing element in result set: %s", err)
			continue
		}
		elements = append(elements, element)
	}

	finisthResult, err := rs.Finish()
	if err != nil {
		return "", []E{}, rs.Err()
	}

	return finisthResult.Bookmark, elements, nil
}

func FilterOperandToCouchDBSelector(filter resources.FilterOption) map[string]interface{} {
	selector := map[string]interface{}{}

	switch filter.FilterOperation {
	case resources.StringEqual:
		selector[filter.Field] = filter.Value
	case resources.StringNotEqual:
		selector[filter.Field] = map[string]interface{}{"$ne": filter.Value}
	case resources.StringContains:
		selector[filter.Field] = map[string]interface{}{"$regex": fmt.Sprintf(".*%s.*", filter.Value)}
	case resources.StringNotContains:
		selector[filter.Field] = map[string]interface{}{"$not": map[string]interface{}{"$regex": fmt.Sprintf(".*%s.*", filter.Value)}}
	case resources.DateEqual, resources.NumberEqual, resources.EnumEqual:
		selector[filter.Field] = filter.Value
	case resources.DateBefore, resources.NumberLessThan:
		selector[filter.Field] = map[string]interface{}{"$lt": filter.Value}
	case resources.DateAfter, resources.NumberGreaterThan:
		selector[filter.Field] = map[string]interface{}{"$gt": filter.Value}
	case resources.NumberNotEqual, resources.EnumNotEqual:
		selector[filter.Field] = map[string]interface{}{"$ne": filter.Value}
	case resources.NumberLessOrEqualThan:
		selector[filter.Field] = map[string]interface{}{"$lte": filter.Value}
	case resources.NumberGreaterOrEqualThan:
		selector[filter.Field] = map[string]interface{}{"$gte": filter.Value}
	}

	return selector
}
