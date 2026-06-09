
<a name="3.8.0"></a>
## [3.8.0](https://github.com/lamassuiot/lamassuiot/compare/shared/http/v3.7.0...3.8.0) (2026-06-09)

### Chores

* Chore: release: prepare release 3.8.0 ([#658](https://github.com/lamassuiot/lamassuiot/issues/658))
* Chore: enhance DEV release workflow with tag validation ([#648](https://github.com/lamassuiot/lamassuiot/issues/648))
* Chore: update Go version from 1.24.x to 1.26.2 across all modules ([#607](https://github.com/lamassuiot/lamassuiot/issues/607))

### Features

* Feat: add CA-to-KMS key migration tool ([#614](https://github.com/lamassuiot/lamassuiot/issues/614))
* Feat: add X.509 certificate extensions support and enhance filtering capabilities ([#407](https://github.com/lamassuiot/lamassuiot/issues/407))
* Feat: improveJSONPath filtering tests for device groups in device manager ([#404](https://github.com/lamassuiot/lamassuiot/issues/404))
* Feat: add OTEL-logrus bridge, and bump dependencies ([#400](https://github.com/lamassuiot/lamassuiot/issues/400))
* Feat: chnage Device Group migration ID to prevent disordered migrations from release 3.7 ([#401](https://github.com/lamassuiot/lamassuiot/issues/401))
* Feat: implement CreateCertificate endpoint and associated logic ([#396](https://github.com/lamassuiot/lamassuiot/issues/396))
* Feat: add support for 384-bit ECDSA keys in AWS Secrets Manager and Vault engines ([#391](https://github.com/lamassuiot/lamassuiot/issues/391))
* Feat: add kms stats endpoint and make all the stats operations filtered ([#387](https://github.com/lamassuiot/lamassuiot/issues/387))

### Fix

* Fix: migrate legacy certificate type values in certificates table ([#645](https://github.com/lamassuiot/lamassuiot/issues/645))
* Fix: improve future-dated certificate validation logic ([#642](https://github.com/lamassuiot/lamassuiot/issues/642))
* Fix: update workflow permissions ([#622](https://github.com/lamassuiot/lamassuiot/issues/622))
* Fix: add grace period to delta monitoring test to prevent race condition ([#606](https://github.com/lamassuiot/lamassuiot/issues/606))
* Fix: Support full client certificate chain extraction and validation ([#406](https://github.com/lamassuiot/lamassuiot/issues/406))
* Fix: upgrade Lamassu modules versions to latest release ([#389](https://github.com/lamassuiot/lamassuiot/issues/389))

### Refactor

* Refactor: Ensure correct context propagation in event publishing and fix CRL service assembly bugs ([#402](https://github.com/lamassuiot/lamassuiot/issues/402))

### Security Fixes

* Security: Update dependencies in go.mod and go.sum ([#398](https://github.com/lamassuiot/lamassuiot/issues/398))
