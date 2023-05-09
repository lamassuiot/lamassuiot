package main

import (
	"context"
	"fmt"

	_ "github.com/go-kivik/couchdb/v4" // The CouchDB driver
	kivik "github.com/go-kivik/kivik/v4"
)

func main() {
	client, err := kivik.New("couch", "http://admin:MPX7WBbg1lIiPV13rKFk@lamassu.zpd.ikerlan.es:5984/", kivik.Options{})
	if err != nil {
		panic(err)
	}

	db := client.DB("dms-manager")

	row := db.Get(context.TODO(), "ed5e94f5ebc565f863e4519abb001e17")
	if err != nil {
		panic(err)
	}

	var cow map[string]interface{}
	if err = row.ScanDoc(&cow); err != nil {
		panic(err)
	}

	fmt.Println(cow)
}
