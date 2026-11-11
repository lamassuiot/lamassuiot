// Command migrate installs or upgrades the Oracle storage schema.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	coreconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/config"
)

func main() {
	timeout := flag.Duration("timeout", 10*time.Minute, "migration timeout")
	flag.Parse()
	cfg := config.Config{
		ConnectString: os.Getenv("LAMASSU_ORACLE_CONNECT_STRING"),
		Username:      os.Getenv("LAMASSU_ORACLE_USERNAME"),
		Password:      coreconfig.Password(os.Getenv("LAMASSU_ORACLE_PASSWORD")),
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := oracle.Migrate(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "oracle migration failed:", err)
		os.Exit(1)
	}
	fmt.Println("Oracle storage migrations applied")
}
