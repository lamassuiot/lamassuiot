
<a name="3.3.0"></a>
## [3.3.0](https://github.com/lamassuiot/lamassuiot/compare/connectors/awsiot/v3.2.2...3.3.0) (2025-03-18)

### Bug Fixes

* Fix: Monolithic: Enable MonitoringJob using negated value of disableMonitor flag ([#234](https://github.com/lamassuiot/lamassuiot/issues/234))
* Fix: Improved gorm queries to reduce it and avoid recordNotFound errors ([#227](https://github.com/lamassuiot/lamassuiot/issues/227))
* Fix: aws eventbus - ensure sns topic exists before subscribing to sns ([#215](https://github.com/lamassuiot/lamassuiot/issues/215))

### Chores

* Chore: launch monolithic UI in a random docker port ([#238](https://github.com/lamassuiot/lamassuiot/issues/238))
* Chore: update contributing guidelines ([#233](https://github.com/lamassuiot/lamassuiot/issues/233))
* Chore: modularize engine registration with build tags to favour custom builds ([#222](https://github.com/lamassuiot/lamassuiot/issues/222))
* Chore: show codecov flag for backend module ([#220](https://github.com/lamassuiot/lamassuiot/issues/220))

### Features

* Feat: DMS Manager: add AWS ALB identity extractor ([#237](https://github.com/lamassuiot/lamassuiot/issues/237))
* Feat: Change device and CA metadata handling by using JSONPatch expressions ([#229](https://github.com/lamassuiot/lamassuiot/issues/229))
* Feat: Add job for scheduled build of CAs CRLs ([#216](https://github.com/lamassuiot/lamassuiot/issues/216))
* Feat: add javascript filters support to subscription conditions ([#221](https://github.com/lamassuiot/lamassuiot/issues/221))
* Feat: aws-connector - report CA registration error in metadata ([#218](https://github.com/lamassuiot/lamassuiot/issues/218))
* Feat: Implement JSONPath and JSONSchema filter options for alert subscriptions  ([#217](https://github.com/lamassuiot/lamassuiot/issues/217))
* Feat: va - add Issuing Distribution Point extension to CRL ([#214](https://github.com/lamassuiot/lamassuiot/issues/214))
* Feat: ca - Add multiple URLs to CRL and OCSP fields in certificates as well as accesing over http instead of https ([#213](https://github.com/lamassuiot/lamassuiot/issues/213))

