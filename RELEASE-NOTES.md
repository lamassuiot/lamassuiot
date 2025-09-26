
<a name="3.5.2"></a>
## [3.5.2](https://github.com/lamassuiot/lamassuiot/compare/engines/storage/postgres/v3.5.1...3.5.2) (2025-09-26)

### Bug Fixes

* Fix: fixed support for dedicated DLQ event bus configuration across services ([#319](https://github.com/lamassuiot/lamassuiot/issues/319))
* Fix: ca: add migration for profile_id with null in validity_time column in ca_certificates table ([#316](https://github.com/lamassuiot/lamassuiot/issues/316))
* Fix: devicemanager: normalize device certificate serial numbers ([#317](https://github.com/lamassuiot/lamassuiot/issues/317))

### Features

* Feat: make issuance profile optional at the certificate sign operation ([#318](https://github.com/lamassuiot/lamassuiot/issues/318))

