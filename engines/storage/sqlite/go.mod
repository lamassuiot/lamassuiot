module github.com/lamassuiot/lamassuiot/engines/storage/sqlite/v3

go 1.22.0

replace (
	github.com/lamassuiot/lamassuiot/core/v3 => ../../../core
	github.com/lamassuiot/lamassuiot/shared/subsystems/v3 => ../../../shared/subsystems
)

require (
	github.com/go-gormigrate/gormigrate/v2 v2.1.3
	github.com/sirupsen/logrus v1.9.3
	gorm.io/driver/sqlite v1.5.6
	gorm.io/gorm v1.25.12
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/mattn/go-sqlite3 v1.14.22 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	github.com/ugorji/go v1.2.12 // indirect
	github.com/ugorji/go/codec v1.2.12 // indirect
	golang.org/x/sys v0.26.0 // indirect
	golang.org/x/text v0.19.0 // indirect
)
