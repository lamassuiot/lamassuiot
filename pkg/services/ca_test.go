package services

import (
	"fmt"
	"testing"

	kivik "github.com/go-kivik/kivik/v4"
	_ "github.com/go-kivik/memorydb" // The Memory driver
	"github.com/lamassuiot/lamassuiot/internal/ca/cryptoengines"
	"github.com/lamassuiot/lamassuiot/pkg/config"
	"github.com/lamassuiot/lamassuiot/pkg/storage/couchdb"
)

func setupTest(t *testing.T) CAService {
	engine, err := cryptoengines.NewGolangPEMEngine("/test")
	if err != nil {
		t.Fatalf("could not create golang PEM engine: %s", err)
		return nil
	}

	couchDBClient, err := kivik.New("memory", "")
	if err != nil {
		t.Fatalf("could not create couchdb in-memory DB: %s", err)
		return nil
	}

	caStorage, err := couchdb.NewCouchCARepository(couchDBClient)
	if err != nil {
		t.Fatalf("could not CA repository: %s", err)
		return nil
	}

	certStorage, err := couchdb.NewCouchCertificateRepository(couchDBClient)
	if err != nil {
		t.Fatalf("could not Cert repository: %s", err)
		return nil
	}

	svc := NeCAService(CAServiceBuilder{
		CryptoEngine:         engine,
		CAStorage:            caStorage,
		CertificateStorage:   certStorage,
		CryptoMonitoringConf: config.CryptoMonitoring{Enabled: false},
	})

	return svc
}

func TestGetCryptoEngineProvider(t *testing.T) {
	csService := setupTest(t)
	engineInfo, err := csService.GetCryptoEngineProvider()
	if err != nil {
		t.Fatalf("could not Cert repository: %s", err)
		return
	}

	fmt.Println(engineInfo)
}
