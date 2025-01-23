
<a name="3.2.0"></a>
## [3.2.0](https://github.com/lamassuiot/lamassuiot/compare/monolithic/v3.1.0...3.2.0) (2025-01-23)

### Bug Fixes

* Fix: EST: add content length in cacerts download with PEM support ([#207](https://github.com/lamassuiot/lamassuiot/issues/207))
* Fix: AWS Connector: use issuer metadata to refer caid ([#204](https://github.com/lamassuiot/lamassuiot/issues/204))
* Fix: add json serialization tags to CACertificate struct
* Fix: monolithic - instantiate filesystem crypto engine with correct conf ([#186](https://github.com/lamassuiot/lamassuiot/issues/186))
* Fix: awsconnector - return error instead of exiting to provide error msg ([#187](https://github.com/lamassuiot/lamassuiot/issues/187))

### Chores

* Chore: CA: reorder migration ca-csr-request ([#208](https://github.com/lamassuiot/lamassuiot/issues/208))
* Chore: clean up codecov configuration ([#196](https://github.com/lamassuiot/lamassuiot/issues/196))
* Chore: configure codecov flags for monorepo ([#192](https://github.com/lamassuiot/lamassuiot/issues/192))
* Chore: simplify dependencies managment ([#183](https://github.com/lamassuiot/lamassuiot/issues/183))
* Chore: simplify relese to just one. Remove releases per each module ([#184](https://github.com/lamassuiot/lamassuiot/issues/184))

### Feat

* Feat: CA - Adding first implementation for issuance profiles ([#206](https://github.com/lamassuiot/lamassuiot/issues/206))
* Feat: create CAs from external signed CSRs ([#202](https://github.com/lamassuiot/lamassuiot/issues/202))
* Feat: CA Service: Add Is CA indicator to certificate entity ([#201](https://github.com/lamassuiot/lamassuiot/issues/201))
* Feat: dmsmamager - allow verifying enroll with external webhook invoke ([#188](https://github.com/lamassuiot/lamassuiot/issues/188))
* Feat: conditional revoke in reenroll for DMS
* Feat: derive keyID from public key instead of random uuid ([#194](https://github.com/lamassuiot/lamassuiot/issues/194))

### Refactor

* Refactor: ca postgres models

### Test

* Test: Add new tests to core module ([#193](https://github.com/lamassuiot/lamassuiot/issues/193))
* Test: fix expiration date tests in TestGetCertificatesByExpirationDate ([#185](https://github.com/lamassuiot/lamassuiot/issues/185))

