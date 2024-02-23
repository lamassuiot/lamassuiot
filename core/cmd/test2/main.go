package main

import (
	"fmt"
	"plugin"
)

func main() {
	kmsPlugin, err := plugin.Open("/home/ikerlan/lamassu/v3.lamassuiot/plugins/submodules/cryptoengines/vault/ce-vault.so")
	chk(err)

	fmt.Println(kmsPlugin)
	// kmsEngineSymbol, err := kmsPlugin.Lookup("NewCryptoEngine")
	// chk(err)

	// fmt.Println(kmsEngineSymbol)

	// var engine interfaces.CryptoEngineBuilder
	// engine, ok := kmsEngineSymbol.(interfaces.CryptoEngineBuilder)
	// if !ok {
	// 	chk(errors.New("unexpected type from module symbol"))
	// }

	// var c = map[string]any{}
	// lgr := helpers.ConfigureLogger(config.Info, "engine")
	// engine.NewCryptoEngine(lgr, c)
}

func chk(err error) {
	if err != nil {
		panic(err)
	}
}
