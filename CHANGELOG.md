
<a name="3.8.1"></a>
## [3.8.1](https://github.com/lamassuiot/lamassuiot/compare/v3.8.0...v3.8.1) (2026-09-17)



### Bug Fixes


* Update header pattern to fully support conventional commits (#663)



### Chores


* Bump the go_modules group across 11 directories with 1 update (#651)

* Bump the go_modules group across 12 directories with 1 update (#671)

* Bump the go_modules group across 13 directories with 1 update (#683)

* Bump the go_modules group across 12 directories with 2 updates (#695)

* Bump google.golang.org/grpc from 1.80.0 to 1.83.1 in /monolithic (#713)

* Bump google.golang.org/grpc from 1.80.0 to 1.83.2 in /engines/fs-storage/localfs (#714)

* Bump github.com/rabbitmq/amqp091-go from 1.11.0 to 1.13.0 in /backend (#715)

* Bump google.golang.org/grpc from 1.80.0 to 1.83.2 in /backend (#716)

* Bump github.com/rabbitmq/amqp091-go from 1.11.0 to 1.13.0 in /monolithic (#722)

* Bump github.com/rabbitmq/amqp091-go from 1.11.0 to 1.13.0 in /engines/eventbus/amqp (#723)

* Bump google.golang.org/grpc from 1.80.0 to 1.83.2 in /sdk (#724)

* Bump google.golang.org/grpc from 1.80.0 to 1.83.2 in /engines/crypto/pkcs11 (#726)

* Bump google.golang.org/grpc from 1.80.0 to 1.83.2 in /engines/crypto/filesystem (#727)

* Bump google.golang.org/grpc from 1.80.0 to 1.83.2 in /engines/crypto/aws (#728)

* Bump google.golang.org/grpc from 1.80.0 to 1.83.2 in /core (#729)

* Bump google.golang.org/grpc from 1.80.0 to 1.83.2 in /connectors/awsiot (#730)

* Bump github.com/rabbitmq/amqp091-go from 1.11.0 to 1.13.0 in /connectors/awsiot (#731)

* Bump google.golang.org/grpc from 1.80.0 to 1.83.2 in /engines/storage/postgres (#732)

* Bump google.golang.org/grpc from 1.80.0 to 1.83.2 in /engines/fs-storage/s3 (#733)

* Bump google.golang.org/grpc from 1.80.0 to 1.83.2 in /engines/crypto/vaultkv2 (#734)

* Bump google.golang.org/grpc from 1.80.0 to 1.83.2 in /engines/crypto/software (#735)

* Bump google.golang.org/grpc from 1.83.1 to 1.83.2 in /monolithic (#736)

* Bump golang.org/x/net (#737)



### Other


* Fix gosec SARIF upload permissions (#725)

* Migrate release changelog workflow to git-cliff (#739)


<a name="3.8.0"></a>
## [3.8.0](https://github.com/lamassuiot/lamassuiot/compare/v3.7.0...v3.8.0) (2026-06-09)



### Features


* Add dynamic device groups support (#380)

* Add kms stats endpoint and make all the stats operations filtered (#387)

* Add support for 384-bit ECDSA keys in AWS Secrets Manager and Vault engines (#391)

* Implement CreateCertificate endpoint and associated logic (#396)

* Feat ca: enhance CN preservation logic in issuance profile application (#392)

* Chnage Device Group migration ID to prevent disordered migrations from release 3.7 (#401)

* Add OTEL-logrus bridge, and bump dependencies (#400)

* ImproveJSONPath filtering tests for device groups in device manager (#404)

* Add X.509 certificate extensions support and enhance filtering capabilities (#407)

* Add CA-to-KMS key migration tool (#614)

* Combined Client Certificate + Webhook auth for EST enrollment (#616)

* Support external webhook auth in reenrollment (#643)

* Add specific auth config for DMS reenroll (#654)



### Bug Fixes


* Upgrade Lamassu modules versions to latest release (#389)

* Support full client certificate chain extraction and validation (#406)

* Add grace period to delta monitoring test to prevent race condition (#606)

* Rename external_webhook JSON field to external_webhook_settings (#618)

* Update workflow permissions (#622)

* Improve future-dated certificate validation logic (#642)

* Propagate logging fields from enrollment helper functions (#646)

* Bump Codecov action to v7 (#657)

* Skip go mod tidy in bump-version when tags don't exist yet



### Security Fixes


* Update dependencies in go.mod and go.sum (#398)



### Chores


* Bump go.opentelemetry.io/otel/sdk from 1.40.0 to 1.43.0 in /engines/storage/postgres (#594)

* Bump go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp from 1.38.0 to 1.43.0 in /monolithic (#593)

* Update Go version from 1.24.x to 1.26.2 across all modules (#607)

* Enhance DEV release workflow with tag validation (#648)

* Release: prepare release 3.8.0 (#658)

* Release: prepare release 3.8.0 (#660)

* Release: prepare release 3.8.0

* Bump module versions to v3.8.0



### Refactor


* Ensure correct context propagation in event publishing and fix CRL service assembly bugs (#402)



### Other


* Add DeepWiki badge to README (#394)

Signed-off-by: Haritz S. Sierra <hsaizsierra@gmail.com>

* Potential fix for code scanning alert no. 345: Workflow does not contain permissions (#397)

Signed-off-by: Juanjo Rodriguez <jjrodrig@gmail.com>
Co-authored-by: Copilot Autofix powered by AI <62310815+github-advanced-security[bot]@users.noreply.github.com>

* Add `in` and `in_ic` filter operators for string and enum fields (#395)

* Update dependencies in go.mod and go.sum (#613)

* Migrate legacy certificate type values in certificates table (#645)

* Fix release workflow token/permissions for Bump Module Versions job (#659)


<a name="3.7.0"></a>
## [3.7.0](https://github.com/lamassuiot/lamassuiot/compare/v3.6.3...v3.7.0) (2026-01-29)



### Features


* Add CA issuance profile support for CreateCA functionality (#371)

* Enable Docker-less local development via SQLite storage and In-Memory bus (#374)

* Implement device filtering statistics functionality (#376)

* Add expiration date info for device identity slots (#377)

* Implement CA reissuance functionality (#357)

* Migrate metadata columns to JSONB and add JSONPath filtering (#378)

* Support sort using jsonpath expressions (#381)

* Transform identity slot into jsonb and make it filterable (#382)

* Add lamassu-db-migration Dockerfile and update references in workflows and README (#383)



### Bug Fixes


* Ca:  Root CA Extended Key Usages (#370)

* Update service name to lamassu-db-migration in docker image work… (#385)



### Chores


* Go dependency cleanup (#364)

* Bump github.com/opencontainers/runc from 1.2.3 to 1.2.8 in /shared/subsystems (#368)

* Bump github.com/eclipse/paho.mqtt.golang from 1.5.0 to 1.5.1 in /connectors/awsiot (#366)

* Bump golang.org/x/crypto from 0.39.0 to 0.45.0 in /monolithic (#367)

* Openapi -  standardize authentication schemes  (#372)

* Add JSON Patch support documentation (RFC 6902) (#379)

* Release: prepare release 3.7.0 (#384)

* Release: prepare release 3.7.0 (#386)



### Refactor


* Isolate backend assembler tests for better coverage and optimize CI timeouts (#365)



### Other


* CA Service to External KMS (#350)

* Add OpenAPI specifications for all APIs (#363)

* Sync workspace deps (#369)

* Feat/observability (#362)


<a name="3.6.3"></a>
## [3.6.3](https://github.com/lamassuiot/lamassuiot/compare/v3.6.2...v3.6.3) (2025-11-17)



### Bug Fixes


* Ca: remove sensitive info in audit events (#356)

* VA ski encoding in crl dp (#358)



### Chores


* Release: prepare release 3.6.3 (#359)


<a name="3.6.2"></a>
## [3.6.2](https://github.com/lamassuiot/lamassuiot/compare/v3.6.1...v3.6.2) (2025-11-11)



### Features


* Add independent database migration tool (#337)



### Bug Fixes


* VA: Use certificate’s actual revocation timestamp in CRL calculation (#333)

* Improve AWS KMS key and alias retrieval with pagination support (#336)

* CA: add issuance profile validation for CA operations (#339)

* AWS Connector: incorrect IoT metadata key in error messages (#340)

* Fixing keysize for aws-based cryptoengines(#353)

* VA: service returns 500 HTTP code for unknown SKIs (#352)



### Tests


* Enabling manual triggering of the workflow (#347)



### Chores


* Adjust test timeout in CI workflow (#348)

* Release: prepare release 3.6.2 (#354)

* Release: prepare release 3.6.2 (#355)


<a name="3.6.1"></a>
## [3.6.1](https://github.com/lamassuiot/lamassuiot/compare/v3.6.0...v3.6.1) (2025-10-10)



### Bug Fixes


* Remove key casting in kms module (#331)



### Chores


* Release: prepare release 3.6.1 (#332)


<a name="3.6.0"></a>
## [3.6.0](https://github.com/lamassuiot/lamassuiot/compare/v3.5.2...v3.6.0) (2025-10-09)



### Features


* Add support to filter certs by subject_key_id (#326)

* KMS Service v1 (#267)

* CA: enhanced CA deletion with cascade operations and private key management (#308)



### Bug Fixes


* Va: use CRL service interface (#322)

* CA: add migration to remove hyphens from issuer_meta_serial_number fields (#325)

* Test configuration and database dependency issues (#327)

* DMS creation date filtering functionality (#329)



### Chores


* Readme update (#323)

* Release: prepare release 3.6.0 (#330)



### Refactor


* Streamline event bus handling and service middleware integration across multiple assemblers (#324)


<a name="3.5.2"></a>
## [3.5.2](https://github.com/lamassuiot/lamassuiot/compare/v3.5.1...v3.5.2) (2025-09-26)



### Features


* Make issuance profile optional at the certificate sign operation (#318)



### Bug Fixes


* Devicemanager: normalize device certificate serial numbers (#317)

* Ca: add migration for profile_id with null in validity_time column in ca_certificates table (#316)

* Fixed support for dedicated DLQ event bus configuration across services (#319)



### Chores


* Release: prepare release 3.5.2 (#320)


<a name="3.5.1"></a>
## [3.5.1](https://github.com/lamassuiot/lamassuiot/compare/v3.5.0...v3.5.1) (2025-09-24)



### Bug Fixes


* Ca: import ca without key when profileid not supplied (#309)

* Monolithic: deploy v4 ui in monolithic with correct port mapping (#310)

* Add missing engines to release finalization workflow (#312)

* All: add correct source in cloud events (#311)



### Chores


* Release: prepare release 3.5.1 (#313)


<a name="3.5.0"></a>
## [3.5.0](https://github.com/lamassuiot/lamassuiot/compare/v3.4.0...v3.5.0) (2025-09-23)



### Features


* DMS Manager: add option to toggle CSR signature verification during Enrollment/Reenrollment (#268)

* Add case-insensitive filtering support (#270)

* Refactor by adding InitCRLRole method to CRLService and its implementations (#271)

* DMS: add certificate Issuance Profile support (#276)

* Va: Remove get roles (#280)

* DMS: implement update metadata endpoint (#283)

* Add PATCH method to metadata endpoints (#284)

* Ca: default issuance profiles for CAs and integrate in dms EST processes (#290)

* Ca: avoid redundancy on issuance profiles generation (#292)

* Add support for deleting devices in decommissioned state (#294)

* Va: add support for CRL certificate reactivation from hold  (#297)

* All: add audit events (#291)

* Add support for filtering CAs based on profile_id (#303)

* Add DELETE certificate endpoint for orphaned certificate cleanup with issuer CA validation (#301)



### Bug Fixes


* Update bookmark encoding to use URL-safe base64 encoding (#272)

* Add the pending signing algorithms (#275)

* No tmp_dir for fileblob persistence (#277)

* Ca: fix crl urls in generated certificates to include hex encoded with colons (#279)

* Middleware: missing DeleteDevice operation

* Allow signing certs expiring after ca (#299)

* Add dlq to event bus after 3 retries (#302)

* Ca: SKI and AKI extracrted from certificates (if any) (#295)



### Tests


* Middleware: add DeleteDevice case to event publisher (#298)



### Chores


* Bump dependencies (#278)

* Monolithic: add labels and standard ports in docker containers (#281)

* Fix linting and typo issues (#287)

* Update CONTRIBUTING.md to clarify setup instructions (#296)

* Refactoring release process (#304)

* Fix release notes in open-pr-release workflow

* Release: prepare release 3.5.0 (#307)



### Refactor


* CA: homogenize certificate SN format (#289)



### Other


* CRL Initialization on event (#273)

* Update dev-release.yaml

Signed-off-by: Haritz S. Sierra <hsaizsierra@gmail.com>

* CA: Add Full CRUD Support for Issuance Profiles in CA Service (#286)


<a name="3.4.0"></a>
## [3.4.0](https://github.com/lamassuiot/lamassuiot/compare/v3.3.0...v3.4.0) (2025-06-04)



### Features


* Enhance event filters to use full event data for processing (#242)

* VA: assemble service conditionally based on config (#244)

* CA: refactor crypto engine keys migration (#246)

* CA: implement AWS KMS import keys (#245)

* DMS Manager: add DMS delete operation (#252)



### Bug Fixes


* Monolithic ui port now being served correctly (#240)

* DMS Manager: add a null check when decommissioning a device wihtout identity (#250)

* DMS Manager: ReEnroll - Add a check to validate the presence of a CommonName in the CSR (#251)

* CA: discard aws reserved kms aliases (#266)

* CA:  fix filtering CAs by CN (#265)



### Bump Versions


* Go-jose to 4.0.5 (#263)

* Backend direct deps (#264)



### Chores


* Adjust monolithic monitoring job (#239)

* Bumping go version 1.24 (#255)

* Bump golang-jwt to 4.5.2 (#258)

* Bump ory/dockertest 3.12.0 (#259)

* Bump aws sdk 1.36.3 (#260)

* Bump go-playground/validator to v10.26.0 (#261)

* Bump x/net to 0.38.0 (#262)



### Other


* Bump x/crypto to v0.38.0 (#257)

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Update CHANGELOG and RELEASE-NOTES


<a name="3.3.0"></a>
## [3.3.0](https://github.com/lamassuiot/lamassuiot/compare/v3.2.2...v3.3.0) (2025-03-18)



### Features


* Ca - Add multiple URLs to CRL and OCSP fields in certificates as well as accesing over http instead of https (#213)

* Va - add Issuing Distribution Point extension to CRL (#214)

* Implement JSONPath and JSONSchema filter options for alert subscriptions  (#217)

* Aws-connector - report CA registration error in metadata (#218)

* Add javascript filters support to subscription conditions (#221)

* Add job for scheduled build of CAs CRLs (#216)

* Change device and CA metadata handling by using JSONPatch expressions (#229)

* Monolithic:lammassui-ui is launched with monolithic. disable-ui flag added to avoid (#232)

* DMS Manager: add AWS ALB identity extractor (#237)



### Bug Fixes


* Aws eventbus - ensure sns topic exists before subscribing to sns (#215)

* Improved gorm queries to reduce it and avoid recordNotFound errors (#227)

* Monolithic: Enable MonitoringJob using negated value of disableMonitor flag (#234)



### Chores


* Show codecov flag for backend module (#220)

* Modularize engine registration with build tags to favour custom builds (#222)

* Update contributing guidelines (#233)

* Launch monolithic UI in a random docker port (#238)



### Other


* Improved ImportCA to update level based on DSN and KID (#224)

* Improved ImportCA to update level based on DSN and KID

Signed-off-by: Cristobal Arellano <carellano@ikerlan.es>

* Refactor x509utils and ca.go to use helper function for self-signed certificate check

Signed-off-by: Cristobal Arellano <carellano@ikerlan.es>

---------

Signed-off-by: Cristobal Arellano <carellano@ikerlan.es>

* Update CHANGELOG and RELEASE-NOTES


<a name="3.2.2"></a>
## [3.2.2](https://github.com/lamassuiot/lamassuiot/compare/v3.2.1...v3.2.2) (2025-01-25)



### Chores


* Rename ci-test worflow (#212)



### Other


* CA - fixed x509 key serialization (#211)

* Update CHANGELOG and RELEASE-NOTES


<a name="3.2.1"></a>
## [3.2.1](https://github.com/lamassuiot/lamassuiot/compare/v3.2.0...v3.2.1) (2025-01-24)



### Bug Fixes


* Hotfix - remove unseting ENV variables befbore PKCS11 proxy connection



### Refactor


* Refactor GetKey for software-based engines (#210)

* refactor GetKey for software-based engines

Signed-off-by: haritz <hsaizsierra@gmail.com>

* added GetKey specific tests

Signed-off-by: haritz <hsaizsierra@gmail.com>

---------

Signed-off-by: haritz <hsaizsierra@gmail.com>



### Other


* Hotfixing ca service renaming

Signed-off-by: haritz <hsaizsierra@gmail.com>

* Move aws connector structures and ID composition logic to connector implementation (#205)

* Add aws-related metadata migration to new schema defined in #166 (#209)

* Update CHANGELOG and RELEASE-NOTES

* Merge branch 'main' of https://github.com/lamassuiot/lamassuiot

* Update CHANGELOG and RELEASE-NOTES

* Update CHANGELOG.md

Signed-off-by: Haritz S. Sierra <hsaizsierra@gmail.com>

* Update CHANGELOG and RELEASE-NOTES

* Update CHANGELOG and RELEASE-NOTES


<a name="3.2.0"></a>
## [3.2.0](https://github.com/lamassuiot/lamassuiot/compare/v3.1.0...v3.2.0) (2025-01-23)



### Features


* Derive keyID from public key instead of random uuid (#194)

* Conditional revoke in reenroll for DMS

* Dmsmamager - allow verifying enroll with external webhook invoke (#188)



### Bug Fixes


* Awsconnector - return error instead of exiting to provide error msg (#187)

* Monolithic - instantiate filesystem crypto engine with correct conf (#186)

* Add json serialization tags to CACertificate struct

* AWS Connector: use issuer metadata to refer caid (#204)

* EST: add content length in cacerts download with PEM support (#207)



### Tests


* Fix expiration date tests in TestGetCertificatesByExpirationDate (#185)



### Chores


* Simplify relese to just one. Remove releases per each module (#184)

* Simplify dependencies managment (#183)

* Configure codecov flags for monorepo (#192)

* Clean up codecov configuration (#196)

* CA: reorder migration ca-csr-request (#208)



### Refactor


* Ca postgres models



### Other


* Add new tests to core module (#193)

* Remove experimental engines (#195)

* CA Service: Add Is CA indicator to certificate entity (#201)

* Create CAs from external signed CSRs (#202)

* CA - Adding first implementation for issuance profiles (#206)

* Update CHANGELOG and RELEASE-NOTES


<a name="3.1.0"></a>
## [3.1.0](https://github.com/lamassuiot/lamassuiot/compare/v3.0.0...v3.1.0) (2024-12-03)



### Bug Fixes


* Fix monolithic cryptoengines spawn

Signed-off-by: haritz <hsaizsierra@gmail.com>



### Chores


* Removing replace from go workspaces (#181)

* Multimodule release workflow (#182)

* Fix release workflow

* Fix release workflow

* Fix release workflow dependencies

* Remove duplicate tasks from release workflow



### Other


* Update CHANGELOG and RELEASE-NOTES

* Update CHANGELOG and RELEASE-NOTES

* Update CHANGELOG and RELEASE-NOTES

* Update CHANGELOG and RELEASE-NOTES


<a name="3.0.0"></a>
## [3.0.0](https://github.com/lamassuiot/lamassuiot/compare/v2.8.0...v3.0.0) (2024-11-26)



### Bug Fixes


* Fix signature tests

Signed-off-by: haritz <hsaizsierra@gmail.com>

* Update module paths to place correct version suffix (#179)



### Chores


* Ci update dockerfiles and gh workflow (#177)

* Fix awsconnector dockerfile



### Refactor


* Major refactor v3 pakage - structured code into go submodules(#176)



### Other


* Update CHANGELOG and RELEASE-NOTES

* Update CHANGELOG and RELEASE-NOTES

* Update CHANGELOG and RELEASE-NOTES

* Update CHANGELOG and RELEASE-NOTES


<a name="2.8.0"></a>
## [2.8.0](https://github.com/lamassuiot/lamassuiot/compare/v2.7.0...v2.8.0) (2024-10-25)



### Features


* DMS: Allow enrollment with expired certificates (#171)



### Bug Fixes


* Alerts: add missing SMTP config to service builder (#168)



### Tests


* DMS Manager: add new test to the EST routes and controller (#169)



### Chores


* Move mapstructure unmantained depency to new ref



### Other


* Allow importing SQL dumps into DBs in docker-launched postgres container (#170)

* AWS IoT Connector: Add additional info in CA registration mode + add SNI CA registration (without private key access) (#166)

* Update CHANGELOG and RELEASE-NOTES


<a name="2.7.0"></a>
## [2.7.0](https://github.com/lamassuiot/lamassuiot/compare/v2.6.0...v2.7.0) (2024-10-02)



### Features


* Add support for Nginx client certificate identity extraction (#161)

* Allow multiple AWS Connectors in a single Lamassu Instance

* Reduce erroneous event processing Intervals in eventbus(#165)



### Bug Fixes


* Fix dev-release workflow

Signed-off-by: haritz <hsaizsierra@gmail.com>

* Fix device manager: handle decomission correctly (#162)

defer cert revocation to prevent race condition triggered by EventBus

Signed-off-by: Haritz Saiz <hsaizsierra@gmail.com>
Co-authored-by: Haritz Saiz <hsaizsierra@gmail.com>



### Chores


* Fix ci release workflow



### Other


* Merge branch 'main' of https://github.com/lamassuiot/lamassuiot

* Merge branch 'main' of https://github.com/lamassuiot/lamassuiot

* Merge branch 'main' of https://github.com/lamassuiot/lamassuiot

* Merge branch 'main' of https://github.com/lamassuiot/lamassuiot

* Update gosec.yml (#163)

* Update gosec.yml

Fix gosec Github Action in workflow

Signed-off-by: Juanjo Rodriguez <jjrodriguez@lksnext.com>

* Update gosec.yml

Signed-off-by: Juanjo Rodriguez <jjrodriguez@lksnext.com>

* Update gosec.yml

Signed-off-by: Juanjo Rodriguez <jjrodriguez@lksnext.com>

---------

Signed-off-by: Juanjo Rodriguez <jjrodriguez@lksnext.com>

* Merge branch 'main' of https://github.com/lamassuiot/lamassuiot

* DMS Manager Add support for EST ServerKeyGen (#123)

* AWS Connector: Improve event description in Device's Events on shadow update (#157)

* Add changelog generation based on commits (#158)

* Actualizar main-release.yaml

* Update CHANGELOG and RELEASE-NOTES

* Merge branch 'main' of https://github.com/lamassuiot/lamassuiot

* Add dependant job in release workflow (#167)

* Merge branch 'main' of https://github.com/lamassuiot/lamassuiot

* Update CHANGELOG and RELEASE-NOTES


<a name="2.6.0"></a>
## [2.6.0](https://github.com/lamassuiot/lamassuiot/compare/v2.5.3...v2.6.0) (2024-08-31)



### Features


* AWS Connector: Handle update certificate status & disconnect things from IoTCore on revoke (#159)



### Other


* Updatable CA issuance expiration

* Missing bookmark filter separator (#147)

* Adding new dev docker image builder workflow (#148)

adding new dev docker image builder workflow

Signed-off-by: haritz <hsaizsierra@gmail.com>

* Fix dev-release workflow (#149)

fix dev-release workflow

Signed-off-by: haritz <hsaizsierra@gmail.com>
Signed-off-by: Haritz S. Sierra <hsaizsierra@gmail.com>

* Add  filters in bookmark when requestd with bookmark already containing filters (#150)

* Revert "Bugfix: Add  filters in bookmark when requestd with bookmark already containing filters" (#151)

Revert "Bugfix: Add  filters in bookmark when requestd with bookmark already …"

This reverts commit 4017a0956bcdd38bd0b19ba67717e2856b75f946.

* Bugfix/bookmark include filters (#152)

* fix dev-release workflow

Signed-off-by: haritz <hsaizsierra@gmail.com>

* adding filters while looping get requests with bookmarks containing filters

Signed-off-by: haritz <hsaizsierra@gmail.com>

* fixing variable names

Signed-off-by: haritz <hsaizsierra@gmail.com>

* reseting bookmark by checking if at least one eleme is remaining tobe fetched

Signed-off-by: haritz <hsaizsierra@gmail.com>

* fixing pagination tests

Signed-off-by: haritz <hsaizsierra@gmail.com>

---------

Signed-off-by: haritz <hsaizsierra@gmail.com>

* Update device status when certifiate is updated to Active from Revoked status (#153)

* Bump github.com/gin-contrib/cors from 1.4.0 to 1.6.0

Bumps [github.com/gin-contrib/cors](https://github.com/gin-contrib/cors) from 1.4.0 to 1.6.0.
- [Release notes](https://github.com/gin-contrib/cors/releases)
- [Changelog](https://github.com/gin-contrib/cors/blob/master/.goreleaser.yaml)
- [Commits](https://github.com/gin-contrib/cors/compare/v1.4.0...v1.6.0)

---
updated-dependencies:
- dependency-name: github.com/gin-contrib/cors
  dependency-type: direct:production
...

Signed-off-by: dependabot[bot] <support@github.com>

* Ensure preventive delta is triggered

Signed-off-by: haritz <hsaizsierra@gmail.com>

* Add infra for mocked aws iot connector event handling tests (#154)

* Add infra for mocked aws iot connector event handling tests
---------

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>
Signed-off-by: haritz <hsaizsierra@gmail.com>
Co-authored-by: haritz <hsaizsierra@gmail.com>

* Bump deps logrus, dockertest and testify

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Bump version of postgres driver


<a name="2.5.3"></a>
## [2.5.3](https://github.com/lamassuiot/lamassuiot/compare/v2.5.2...v2.5.3) (2024-07-16)



### Other


* Allow filtering CAs by CN (#142)

allow filtering CAs by CN

Signed-off-by: Haritz Saiz <hsaizsierra@gmail.com>

* Monolithic Fix: renable pkcs11 cryptoengine if configured (#143)

renable pkcs11 cryptoengine if configured~

Signed-off-by: Haritz Saiz <hsaizsierra@gmail.com>

* Fixing vault restart path check (#145)

fixing vault restart path check

Signed-off-by: Haritz Saiz <hsaizsierra@gmail.com>


<a name="2.5.2"></a>
## [2.5.2](https://github.com/lamassuiot/lamassuiot/compare/v2.5.1...v2.5.2) (2024-06-21)



### Tests


* Add mock based test to event publisher middelwares  (#120)

* Refactor to start event buses once during tests (#141)



### Chores


* Remove unused swagger support (#118)

* Customize codecov integration (#133)



### Refactor


* Make event handlers first-class citizens in our code (#121)



### Other


* Storage engine refactor - Decouple assemblers from storage engines (#115)

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Add test to storage engine builder (#116)

* Add test to storage engine builder
* Add test to AWS SDK config loading

* Fixes hardcoded queue name (#110)

* Fixes hardcoded queue name

Signed-off-by: Mikel Amuchastegui Zubizarreta <mamuchastegui@lksnext.com>

* Sets default queue name for backwards compatibility

Signed-off-by: Mikel Amuchastegui Zubizarreta <mamuchastegui@lksnext.com>

* Fixes comma typo

Signed-off-by: Mikel Amuchastegui Zubizarreta <mamuchastegui@lksnext.com>

* Uses Viper library option to set default values in configurations and adds the chance to set default values for all services configurations

Signed-off-by: Mikel Amuchastegui Zubizarreta <mamuchastegui@lksnext.com>

* Fixes typo when loading config from standard path

Signed-off-by: Mikel Amuchastegui Zubizarreta <mamuchastegui@lksnext.com>

* Use instances of the config struct to pass default values

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

---------

Signed-off-by: Mikel Amuchastegui Zubizarreta <mamuchastegui@lksnext.com>
Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>
Co-authored-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Add tests for cryptoengines based on support containers (#117)

* Test - Add tests for cryptoengines based on support containers

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* changing AWS KMS-Signer wrapper that supports both PKCS1_V15 and PSS

Signed-off-by: haritz <hsaizsierra@gmail.com>

* simplify salt calculation for RSA-PSS signatures

Signed-off-by: haritz <hsaizsierra@gmail.com>

* simplifying AwsKms-Crypto.Signer wrapper

Signed-off-by: haritz <hsaizsierra@gmail.com>

* fixing RSA-PSS signature-verify

Signed-off-by: haritz <hsaizsierra@gmail.com>

* Use same supporting container for each crypto engine test suite

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* removing unused code

Signed-off-by: haritz <hsaizsierra@gmail.com>

---------

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>
Signed-off-by: haritz <hsaizsierra@gmail.com>
Co-authored-by: haritz <hsaizsierra@gmail.com>

* Decouple crypto monitor logic from CA Service (#119)

* Decouple crypto monitor logic from CA Service
* Test: Fix importCA test failling due to expired hardcoded CA certificate

---------

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Update DMS Update event key (#113)

fixing actual usage of the update dms event

Signed-off-by: haritz <hsaizsierra@gmail.com>

* Use golang build tags to customize build  (#124)

chore: use golang build tags to customize build by excluding experimental features and remove incompatible functionallity on windows

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* No storage engine was registered as main is only executed on package load

* Introduce SQLite Storage Engine and Customization Flags for Monolithic Lamassu IoT (#126)

* hotfix: no storage engine was registered as main is only executed on package load

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* feat: add sqlite storage engine only intended for development

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* feat: Add flags to use sqlite storage engine and disable cryptomonitor

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Add experimental tag to SQLite storage engine. As it is not intended for production usage

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Add disable eventbus flag to monolithic launcher

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Change golang cryptoengine name to golangfs and set it as default

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* A bit of fun

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

---------

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Implementing storage interfaces for CouchDB (#73)

Implemented all Repository interfaces using CouchDB
- Added experimental tag to CouchDB storage files
- Modified CouchDB implementation to handle the lack of counting support
- Ensure that experimental features do not break the build in CI

* Configuring codecov job for checking the difference in the test coverage (#129)

Condifiguring codecov job

Signed-off-by: mgalparsoro <95476185+mgalparsoro@users.noreply.github.com>

* Create pull_request_template (#131)

Signed-off-by: Haritz S. Sierra <hsaizsierra@gmail.com>

* Removing dot typo

Signed-off-by: Haritz S. Sierra <hsaizsierra@gmail.com>

* Updating codecov github action (#132)

* a change done in ci-test

* delete workflow test coverage

* Update ci-test.yaml

Signed-off-by: mgalparsoro <95476185+mgalparsoro@users.noreply.github.com>

* Update ci-test.yaml

Signed-off-by: mgalparsoro <95476185+mgalparsoro@users.noreply.github.com>

* Delete .github/workflows/main-push.yaml

Signed-off-by: mgalparsoro <95476185+mgalparsoro@users.noreply.github.com>

* Update ci-test.yaml

Signed-off-by: mgalparsoro <95476185+mgalparsoro@users.noreply.github.com>

---------

Signed-off-by: mgalparsoro <95476185+mgalparsoro@users.noreply.github.com>

* Update README.md

Signed-off-by: Haritz S. Sierra <hsaizsierra@gmail.com>

* Update ci-test.yaml

Signed-off-by: Haritz S. Sierra <hsaizsierra@gmail.com>

* Update ci-test.yaml

Signed-off-by: Haritz S. Sierra <hsaizsierra@gmail.com>

* Adding basic tests to EventBus (#135)

* adding basic tests to EventBus

Signed-off-by: haritz <hsaizsierra@gmail.com>

* wait publishg with sleep

Signed-off-by: haritz <hsaizsierra@gmail.com>

* fixing RunAsync with error report

Signed-off-by: haritz <hsaizsierra@gmail.com>

* increase tests timeout from 10m to 15m

Signed-off-by: haritz <hsaizsierra@gmail.com>

---------

Signed-off-by: haritz <hsaizsierra@gmail.com>

* CA testing: New tests (#134)

adding tests to CA service

Signed-off-by: haritz <hsaizsierra@gmail.com>

* EST CACerts tests (#136)

* Adding content-length to EST endpoints (#139)

adding content-length to EST endpoints

Signed-off-by: haritz <hsaizsierra@gmail.com>

* Check DMS ownership on enrollment (#130)

check dms ownership on enrollment

Signed-off-by: haritz <hsaizsierra@gmail.com>

* Pagination optimization(#138)

* CA testing: New tests (#134)

adding tests to CA service

Signed-off-by: haritz <hsaizsierra@gmail.com>
Signed-off-by: Manex Galparsoro <mgalparsoro@ikerlan.es>

* Optimization of the pagination and getAllDevices tested

Signed-off-by: Manex Galparsoro <mgalparsoro@ikerlan.es>

* Testing getDeviceStats and getDevicesByDMS

Signed-off-by: Manex Galparsoro <mgalparsoro@ikerlan.es>

* TestGetDeviceByID done

Signed-off-by: Manex Galparsoro <mgalparsoro@ikerlan.es>

* more device manager and dms tests

Signed-off-by: Manex Galparsoro <mgalparsoro@ikerlan.es>

---------

Signed-off-by: haritz <hsaizsierra@gmail.com>
Signed-off-by: Manex Galparsoro <mgalparsoro@ikerlan.es>
Signed-off-by: Haritz S. Sierra <hsaizsierra@gmail.com>
Co-authored-by: Haritz S. Sierra <hsaizsierra@gmail.com>


<a name="2.5.1"></a>
## [2.5.1](https://github.com/lamassuiot/lamassuiot/compare/v2.5.0...v2.5.1) (2024-05-09)



### Removed


* Remove go.work file

Signed-off-by: haritz <hsaizsierra@gmail.com>



### Other


* Adding monoitcally increasing CRL number as defined in RFC5280 + bump to go 1.22

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* Using patch version in go version within go.mid

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* Adding coverage report in PRs

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* Adding go version bump action (#96)

* Adding go version bump action

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* Minor fix of job name id

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

---------

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* Fix Go Bump action (#97)

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* Fixing bump goversion workflow (#98)

fixing bump goversion workflow

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* Bumping go version to 1.22.1 (#99)

Bump go version to 1.22.1

Signed-off-by: Lamassu GH Action <lamassu-action@users.noreply.github.com>
Co-authored-by: Lamassu GH Action <lamassu-action@users.noreply.github.com>

* Bump github.com/cloudevents/sdk-go/v2 from 2.11.0 to 2.15.2

Bumps [github.com/cloudevents/sdk-go/v2](https://github.com/cloudevents/sdk-go) from 2.11.0 to 2.15.2.
- [Release notes](https://github.com/cloudevents/sdk-go/releases)
- [Commits](https://github.com/cloudevents/sdk-go/compare/v2.11.0...v2.15.2)

---
updated-dependencies:
- dependency-name: github.com/cloudevents/sdk-go/v2
  dependency-type: direct:production
...

Signed-off-by: dependabot[bot] <support@github.com>

* Refactor EventBus with high-level functions (#102)

* refactoring watermill with HighLevel funcs and MW

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* adjusting Watermill usage with middlewares

Signed-off-by: haritzsaiz <hsaizsierra@gmail.com>

* SQS-SNS Event provider + adding event bus tests

Signed-off-by: haritzsaiz <hsaizsierra@gmail.com>

* first working version with watermill and SQS-SNS

Signed-off-by: haritzsaiz <hsaizsierra@gmail.com>

* refactored AWS SNS-SQS implementation into exchanges

Signed-off-by: haritzsaiz <hsaizsierra@gmail.com>

* adding more tests for enrollment/reenrollment event generation

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* refactored logger to include better svc tracing + exposing handler func

Signed-off-by: haritzsaiz <hsaizsierra@gmail.com>

* fixing for loop

Signed-off-by: haritzsaiz <hsaizsierra@gmail.com>

* removing amqp creds leak in logging

Signed-off-by: haritzsaiz <hsaizsierra@gmail.com>

---------

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>
Signed-off-by: haritzsaiz <hsaizsierra@gmail.com>

* Extends AWS Authentication methods (#103)

* Adds option for temporary credentials in AWS connector

Signed-off-by: Mikel Amuchastegui Zubizarreta <mamuchastegui@lksnext.com>

* Adds AWS authentication method with assume role

Signed-off-by: Mikel Amuchastegui Zubizarreta <mamuchastegui@lksnext.com>

* Fixes assume role authentication

Signed-off-by: Mikel Amuchastegui Zubizarreta <mamuchastegui@lksnext.com>

* Adds default authentication when authentication method is not detected

Signed-off-by: Mikel Amuchastegui Zubizarreta <mamuchastegui@lksnext.com>

* Refactors to avoid duplicated code

Signed-off-by: Mikel Amuchastegui Zubizarreta <mamuchastegui@lksnext.com>

---------

Signed-off-by: Mikel Amuchastegui Zubizarreta <mamuchastegui@lksnext.com>

* Minor code cleanup (#104)

Code clean up

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Remove coverage in CI (#106)

remove coverage

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* Fix - Restore cron scheduller stop during test suite shutdown (#105)

* Fix - Restore cron scheduller stop during test suite shutdown

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* fixing CA after suite

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* Fix - Test shutdown process - Reorder services shutdown

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

---------

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>
Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>
Co-authored-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* Adding flexibility for creating SelfSigned CAs + Adding ARN to cert metadata (#84)

* adding flexibility for creating SelfSigned CAs + adding ARN to cert metadata for registered certs

Signed-off-by: Manex Galparsoro <mgalparsoro@ikerlan.es>

* fixing compilation issue

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

---------

Signed-off-by: Manex Galparsoro <mgalparsoro@ikerlan.es>
Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>
Co-authored-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* Create SECURITY.md

Signed-off-by: Juanjo Rodriguez <jjrodriguez@lksnext.com>

* Minor code quaility refactor of assemblers module

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Code clean up at x509engines module

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Refactor - fix linter warnings

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Remove unused swagger dependecnies

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Refactoring logging system (#111)

* adding request IDs to CAService

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* adding context to all services functions + adding contextual logger for all services functions + adding context to db ops

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* refactoring logger config names + adding caller ID to logs

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* fixing context in selectAll and helpers logging test

Signed-off-by: haritz <hsaizsierra@gmail.com>

* adding new gin middlewares + better tracing

Signed-off-by: haritz <hsaizsierra@gmail.com>

* fixing engine retrival log message + using correct logging variables for req-id

Signed-off-by: haritz <hsaizsierra@gmail.com>

* removing external gindump into managed functionality

Signed-off-by: haritz <hsaizsierra@gmail.com>

---------
Signed-off-by: haritz <hsaizsierra@gmail.com>

* Bump viper version to 1.18.2

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Config loader tests

* Remove usage of experimental go features for slices package

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Fix null-loggers & remove global loggers (#114)

removing global logers

Signed-off-by: haritz <hsaizsierra@gmail.com>


<a name="2.5.0"></a>
## [2.5.0](https://github.com/lamassuiot/lamassuiot/compare/v2.4.6...v2.5.0) (2024-02-22)



### Other


* Adding threatsafe protection in msg handling for AWS IoT and Alerts (#92)


<a name="2.4.6"></a>
## [2.4.6](https://github.com/lamassuiot/lamassuiot/compare/v2.4.5...v2.4.6) (2024-02-13)



### Other


* Fix first event storage at eventstore. (#90)

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Standardize times in dockerfile to iso8601 and fixing debug pg time …deltas (#91)

standarizing times in dockerfile to iso8601 and fixing debug pg time deltas

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>


<a name="2.4.5"></a>
## [2.4.5](https://github.com/lamassuiot/lamassuiot/compare/v2.4.4...v2.4.5) (2024-02-10)



### Other


* Fix DMS Reenroll: Return error if secondary CA validation also fails (#86)

* return error if secondary validation is not valid

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* adding more EST-DMS tests

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* fixing err/prergistration err checking in enroll test

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* adding more tests + fixing coverage reported in CI

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* adding PEM accept tests

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* adding a cron stop mechanism + fix https insecure test client

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

---------

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* Add Import CA hierarchy functionality (#88)

adding import CA hierarchy test

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* Prevent creating empty CA subject fields (#89)

prevent using empty subject fields

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* Reorder reenroll expiration check (#87)

reorder reenroll expiration check

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>


<a name="2.4.4"></a>
## [2.4.4](https://github.com/lamassuiot/lamassuiot/compare/v2.4.3...v2.4.4) (2024-02-05)



### Chores


* Upgrade actions to node 20



### Other


* (ci) - Fix merge main into major release branch (#80)

Fix merge main into major release branch (vx). Unshallow fetch required to merge

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Adding firsts EST enroll test + Dynamic coverage badge in README (#81)

adding firsts EST enroll test + dynamic coverage badge in README

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* Bump github.com/opencontainers/runc from 1.1.6 to 1.1.12

Bumps [github.com/opencontainers/runc](https://github.com/opencontainers/runc) from 1.1.6 to 1.1.12.
- [Release notes](https://github.com/opencontainers/runc/releases)
- [Changelog](https://github.com/opencontainers/runc/blob/v1.1.12/CHANGELOG.md)
- [Commits](https://github.com/opencontainers/runc/compare/v1.1.6...v1.1.12)

---
updated-dependencies:
- dependency-name: github.com/opencontainers/runc
  dependency-type: indirect
...

Signed-off-by: dependabot[bot] <support@github.com>

* Adding panic-safe message handling to Device Manager (#85)

* adding panic-safe message handling

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* refactoring and cleaning code

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

---------

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>


<a name="2.4.3"></a>
## [2.4.3](https://github.com/lamassuiot/lamassuiot/compare/v2.4.2...v2.4.3) (2024-01-31)



### Other


* Prevent revoking non-active device certificate on ReEnroll (#79)

prevent revoking non-active device cert

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>

* Prevent Panic while handling a cloud event with null data (#78)

fixing possible null data in cloud event that would cause panic

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>


<a name="2.4.2"></a>
## [2.4.2](https://github.com/lamassuiot/lamassuiot/compare/v2.4.1...v2.4.2) (2024-01-29)



### Bug Fixes


* Fix durationToString while using nanoseconds (#43)

* Fixing watermill ack & correct certificate expiration

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>

* Fixed missing function call naming refactor

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>

* Simplify conditional branch and resolve minor lintter issues

* Use correct syntax for vars



### Other


* (ci): add an automated workflow for release  (#42)

* Compute version name for tag, release and branch

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>

* Use personal tokens for mege

Signed-off-by: Juanjo Rodriguez <jjrodriguez@lksnext.com>

* ci - Start release by freezing a release branch

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Remove .git from Dockerfiles

Signed-off-by: Juanjo Rodriguez  <jjrodriguez@lksnext.com>

---------

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>
Signed-off-by: Juanjo Rodriguez <jjrodriguez@lksnext.com>
Co-authored-by: Saiz Haritz <hsaizsierra@gmail.com>

* Rename method to checkCertificateRevocation

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>

* Add workflow for testing

* Fix typo and apply gofmt simplify (#44)

Add device id to the log

Signed-off-by: Juanjo Rodriguez <jjrodriguez@lksnext.com>

* Pretty print test results

* Reduce log level, skip unreliable tests and manage ignored errors in tests

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Launch tests on PR create or update

* Proposal for removing support for test infrastructure deployment (#50)

Remove support for test infraestructure deployment

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Fix dependabot security alerts upgrading dependencies (#51)

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Bump github.com/go-jose/go-jose/v3 from 3.0.0 to 3.0.1

Bumps [github.com/go-jose/go-jose/v3](https://github.com/go-jose/go-jose) from 3.0.0 to 3.0.1.
- [Release notes](https://github.com/go-jose/go-jose/releases)
- [Changelog](https://github.com/go-jose/go-jose/blob/main/CHANGELOG.md)
- [Commits](https://github.com/go-jose/go-jose/compare/v3.0.0...v3.0.1)

---
updated-dependencies:
- dependency-name: github.com/go-jose/go-jose/v3
  dependency-type: indirect
...

Signed-off-by: dependabot[bot] <support@github.com>

* SQL Injection  (#55)

addjusting variable name and sql injection prevention

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* Add Gosec to CI (#54)

* Add Gosec to CI 
* Exclude rule G104
* Exclude rule G601

Signed-off-by: Juanjo Rodriguez <jjrodriguez@lksnext.com>

* CI - Gosec - Add push on main branch event

Signed-off-by: Juanjo Rodriguez <jjrodriguez@lksnext.com>

* Fix unordered slices comparison

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Add unit testing for helpers

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Add test for messaging utils and disable unreliable test

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Remove unused funtion x509fingerprint

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Restric file permissions to owner

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Add tests for file sourced certs and keys

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Tweaked postgres ops to improve performance

Signed-off-by: Cristobal Arellano <carellano@ikerlan.es>

* Adapt interfaces to improve consistency

Signed-off-by: Cristobal Arellano <carellano@ikerlan.es>

* Tweaked postgres ops to improve performance (#65)

* Prevent "soft" SQL injections (#67)

check if field is allowed to be used in query

Signed-off-by: Cristobal Arellano <carellano@ikerlan.es>

* Add unit tests to filesystem based crypto engine (#64)

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Tests - Add tests to X509Criptoengine (#68)

* Add tests to x509engine

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Fix - Error validating signature using EC with hashed input

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

---------

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* E2E Usecase1 test. CSR signing with extensions and more key usages (#69)

* adding usecase test 1 + csr signing with extensions and augmented keyusage

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>

* using https instead of http in OCSP and CRL variables

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>

* skipping usecase 1 test

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>

* generalizing extension generation test

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>

---------

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>

* Fix config AMQP tag typo (#71)

fixed config tag typo

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>

* Integration tests for Device Manager service

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Refactor - Move test server assembling logic to a common place

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Improve organization of BeforeEach and AfterSuite logic

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Fix typo in filename

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Adding existing logic to check for CA expiration deltas and fixed test typo (#74)

adding existing logic to check for CA expiration deltas and fixed testfunc typo

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>

* Removed as PrivateKey from models is not used

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Fix duration to string year and weeks and new tests

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Adding basic CAs in docker image + serializing error correctly in EST (#77)

adding basic CAs in docker image + seralizing error correctly in EST

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* Rename dms_id param within DeviceManager (#76)

renaming dms_id param

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>


<a name="2.4.1"></a>
## [2.4.1](https://github.com/lamassuiot/lamassuiot/compare/v2.4.0...v2.4.1) (2023-12-21)



### Bug Fixes


* Reduce docker images surface (#36)

* Fix(sonar) - Reduce ca image surface

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Fix(sonar) - Reduce ca image surface (#40)

* Use versions computed externally

* Use versions computed externally (#41)



### Other


* Replacing AsyncMessaging with watermill lib (#37)

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>

* Refactoring dependecies system (#38)

* deleting vendor folder and refactoring CI and dockerfiles

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>

* adding go package auto publish into branch w/ Github Action

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>

---------

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>

* Fixing if structure in github action

* Regex for checking semver fix

* Setenv replaced with secure commands

* Removing changelog file as non exists

* Changing env usage in action

* Added missing refact

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>

* Added missing refact (#39)


<a name="2.4.0"></a>
## [2.4.0](https://github.com/lamassuiot/lamassuiot/compare/v0.0.6...v2.4.0) (2023-12-20)



### Bug Fixes


* Fixing image naming

* Fixed vendor folder sync (#27)

* Fixing github actions. Adapt to new naming convention (#28)

fixing github actions

* Remove code duplications (#33)



### Other


* Release 2.2 (#18)

* Update Sign & Verify

* Add Import CA Endpoint

* Add the variable WithPrivatekey to the http payload of the CA

* Update Verify and Enroll functions

* Remove BD docker build

Signed-off-by: Haritz S. Sierra <31985294+haritzsaiz@users.noreply.github.com>

* Update Device Manager Unit Tests and add email template (#20)

* Update Alerts, DevManager and OCSP Tests & add email.html template

* Update Device Manager tests

* Fix DMS enroll (#21)

fixed enroll validation client cert

* Relase candidate for 2.3 (#26)

* pre cloudproxy integration with azure

* Refactoring in progress

* implemented iterateDeviceWithPredicate

* core services refactored

* Fixed Get Devices endpoint

* added mail service

* added new tests

* Tests: Initial version

* Revert "Tests: Initial version"

This reverts commit 8cef5398ad44655cd283220a3d67b337dd1a1a14

* Update tests

* new alerts functionalities

* Validation files added

* Validation and logging

* Update

* Vault Service

* Update Vault Service

* local changes

* alerts progress

* alert - fix: empty user subs now returns empty list instead of err

* refactored lamassu + alerts service

* infra: fix tests file paths

* infra: renamed 'dms enroller' refs to 'dms managwer'

* infra: trigger on workflow file update

* infra: fix test ca file paths

* New Alerts service + general refactor

Co-authored-by: Saiz Haritz <hsaiz@ikerlan.es>
Co-authored-by: Hernandez Elena <Ehernandez@ikerlan.es>
Co-authored-by: jporres <jporres@ikerlan.es>

* infra: fx new db dockerfile name

* infra - aws: fix corrupted npm sha ref

* fix critical reenroll bug

* ocsp + critical reenroll fix

* remove redundant certificate validation

* removed unused test app

* change EC2 deployment script

* fix aws cdk library integrity check

* fix EC2 lamassu install script

* bumping docker compose version installed on EC2

* removed Jaeger/otel config

* removed all otel references

* Refactored services into one

* testing new periodic certs checking system

* fixed and rearchitected scan system

* fixing ocsp key parsing format

* Update EST Response

* allow non TLS connections for AMQP, HTTP server and Vault

* Develop (#6)

* removed Jaeger/otel config

* removed all otel references

* Refactored services into one

* testing new periodic certs checking system

* fixed and rearchitected scan system

* fixing ocsp key parsing format

* Update EST Response

* allow non TLS connections for AMQP, HTTP server and Vault

Co-authored-by: Saiz Haritz <hsaiz@ikerlan.es>

* fixed AMQP certificate load only in TLS mode

* adding AMQP UserPass support

* added support for HTTP or HTTPS for Lamassu Clients

* Adding AMQP reconnection logic

* Refactored logging system

* fixed POSTGRES_USERNAME for CA + sqlite dependency

* fixing type

* limiting gopem RSA keysize

* fixed service middleware autoref arquitectural problem

* fixing DMS Authorization test

* adding timestamp to logs + newVaultEngine autounseal optional + new ca scan optional

* general fixes

* Update alerts and AWSKMS

* adding cloud hosted DMS

* patch(json_path): fixed json path condition filtering

Signed-off-by: Saiz Haritz <hsaiz@ikerlan.es>
Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>

* patch(github actions): changed actions to use version instead of tag

Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>

* findus things

* adding updated go mod files

* Add DMS name to device & Update AWS Device Shadow

* Add the AllowNewEnrollment functionality in the DMS and device manager, add the AllowExpiredRenewal functionality in the DMS and add the functionality to create a CA indicating a fixed date or duration.

* Fix deviceManager, CA & DmsManager services tests

* Update the SignCertificateRequest endpoint and add the AwsSecretManager implementation

* Update Device Manager Reenroll function verify DMS Certificate with UpstreamCA

* Update Reenroll function when cloud Dms is false

* Migrate images from Dockerhub services to Github Registry

* Update Github Workflows

* Update DMS AMQP Middleware and Create Get Devices By DMS endpoint

* Update tag generator

* refactoring CA service

* Fixing cross csr signature

* adding vaultkv2 support. pending import methods

* Update the issuance Expiration type of the databse when creating a CA

* advanced logging

* refactoring core svc to v3

* refactoring to v3

* cloud connector

* adding vendor

* Update EST Client: Add APS to reenroll endpoint & Add extra validation CAs to DMS Reenroll options

* v3 dev

* Integrate Lamassu CA V3 client

* Update services to use the CA V3 client

* adding ctx to CA calls to log req-id

* merging V3 and V2

* Add the cryptographic engine ID when creating/importing a CA

* added psql bookmarking

* postgres bookmark

* Add client certificate verification recursion level in enrollment

* Rename chain_validation_level and additional_validation_cas

* Adding new ca features

* update develop branch with v3 version

* refactoring to constant events types and aws iot development

* merging v3 with develop

* untracking cmd/test

* Feature/standard revoke reason (#24)

* added revocation reason in OCSP and CRL. added new go type for config secrets. fixed v3 listing elements in controller

* fixed bugs

* Feature/postgres testing (#25)

* added revocation reason in OCSP and CRL. added new go type for config secrets. fixed v3 listing elements in controller

* fixed bugs

* added basic testing infra

* fixed enroll validation

* fixed JITP and DevManager enroll

* added device-manager main changes

---------

Signed-off-by: Saiz Haritz <hsaiz@ikerlan.es>
Signed-off-by: Saiz Haritz <hsaizsierra@gmail.com>
Co-authored-by: Saiz Haritz <hsaiz@ikerlan.es>
Co-authored-by: Ubuntu <ubuntu@ubuntu2110.linuxvmimages.local>
Co-authored-by: Hernandez Elena <Ehernandez@ikerlan.es>
Co-authored-by: jporres <jporres@ikerlan.es>

* Bugfix/fix ci releaseflow (#29)

* fixing github actions

* fixed ca dockerfile name

* Bugfix/fix ci releaseflow (#30)

* fixing github actions

* fixed ca dockerfile name

* fixed alerts and cloud proxy with latest go version

* Disabled cross compilation cloud-proxy

* Release 2.4.0 (#31)

* first interface generic draft

* Testing CA client

* removed aws sdk v1 -> v2

* update vendor

* git commit with errors

* mastests

* added main refactor to v3 style

* more tests

* more tests

* added new metadata keys for auto register

* refactoring dms & device with enroll/reenroll support

* ignoring cmd/test folder

* updating automation structures

* remooving unecessary code

* Removing legacy code

* firsr complete iot-automation

* added CA filters

* changing device ID slot to store SN not Certificate model

* removed aws sdk v1

* updating dependencies

* refactoring alerts

* Refactoring Annotation System

* monolithic DEV version

* updating vendor

* fixing aws main

* monolithic dev

* monolithic dev

* Fixinig bugs

* tunning aws support

* patching test cmd

* fixing things

* adding pkcs11 + fix new alerts dockerfile

* CA hierarchy tests

* storage list simplified query

* some checks in the tests

* testing the cryptoengines with hierarchies

* fixing iter issue + ca revocation + device decommissioning + force updates w shadows

* Fix typo in startup message

Signed-off-by: Juanjo Rodriguez <jjrodriguez@lksnext.com>

* adding import certificate endpoint

* solving the problem of parent ca

* fixed aws reenroll sync cert

* fixing amq cloud events

* fixing kms + adding vault root token print in monolithic version

* fixing parent engine

* fixed KMS Signer auth while using localstack

* fixed AWS ResolverV2 failure by bumping SDK version

* renaming device status + rolling back EST

* rolling back to gloablan sign EST

* adding ocsp and crl validation with external CAs on Enroll/Renroll

* fixed dms main logger + bind crt to device in dms

* implementing client cert import

* adding bind mode in http client + implementing import cert sdk call

* fixed crypto engine problem

* Developing import key vault functionality

* Ensuring the import key functionality

---------

Signed-off-by: Juanjo Rodriguez <jjrodriguez@lksnext.com>
Co-authored-by: Juanjo Rodriguez <jjrodriguez@lksnext.com>

* Removing cloud-proxy & adding aws-connector

* Fix sonar - Remove this conditional structure or edit its code blocks so that they're not all the same. (#32)

Fix sonar - conditioned result

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Fix sonar - Add cleanning steps to dockerfiles (#34)

* fix(sonar): Clean apt cache

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* Add clean steps to ca dockerfile

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

---------

Signed-off-by: Juan Jose Rodriguez <jjrodriguez@lksnext.com>

* V2.4.0 (#35)


<a name="0.0.6"></a>
## [0.0.6](https://github.com/lamassuiot/lamassuiot/compare/v0.0.5...v0.0.6) (2023-01-13)



### Other


* Release 2.0.0 (#15)

* pre cloudproxy integration with azure

* Refactoring in progress

* implemented iterateDeviceWithPredicate

* core services refactored

* Fixed Get Devices endpoint

* added mail service

* added new tests

* Tests: Initial version

* Revert "Tests: Initial version"

This reverts commit 8cef5398ad44655cd283220a3d67b337dd1a1a14

* Update tests

* new alerts functionalities

* Validation files added

* Validation and logging

* Update

* Vault Service

* Update Vault Service

* local changes

* alerts progress

* alert - fix: empty user subs now returns empty list instead of err

* refactored lamassu + alerts service

* infra: fix tests file paths

* infra: renamed 'dms enroller' refs to 'dms managwer'

* infra: trigger on workflow file update

* infra: fix test ca file paths

* New Alerts service + general refactor

Co-authored-by: Saiz Haritz <hsaiz@ikerlan.es>
Co-authored-by: Hernandez Elena <Ehernandez@ikerlan.es>
Co-authored-by: jporres <jporres@ikerlan.es>

* infra: fx new db dockerfile name

* infra - aws: fix corrupted npm sha ref

* fix critical reenroll bug

* ocsp + critical reenroll fix

* remove redundant certificate validation

* removed unused test app

* change EC2 deployment script

* fix aws cdk library integrity check

* fix EC2 lamassu install script

* bumping docker compose version installed on EC2

* removed Jaeger/otel config

* removed all otel references

* Refactored services into one

* testing new periodic certs checking system

* fixed and rearchitected scan system

* fixing ocsp key parsing format

* Update EST Response

* allow non TLS connections for AMQP, HTTP server and Vault

* Develop (#6)

* removed Jaeger/otel config

* removed all otel references

* Refactored services into one

* testing new periodic certs checking system

* fixed and rearchitected scan system

* fixing ocsp key parsing format

* Update EST Response

* allow non TLS connections for AMQP, HTTP server and Vault

Co-authored-by: Saiz Haritz <hsaiz@ikerlan.es>

* fixed AMQP certificate load only in TLS mode

* adding AMQP UserPass support

* Develop (#7)

* removed Jaeger/otel config

* removed all otel references

* Refactored services into one

* testing new periodic certs checking system

* fixed and rearchitected scan system

* fixing ocsp key parsing format

* Update EST Response

* allow non TLS connections for AMQP, HTTP server and Vault

* fixed AMQP certificate load only in TLS mode

* adding AMQP UserPass support

Co-authored-by: Saiz Haritz <hsaiz@ikerlan.es>

* added support for HTTP or HTTPS for Lamassu Clients

* Adding AMQP reconnection logic

* Refactored logging system

* fixed POSTGRES_USERNAME for CA + sqlite dependency

* fixing type

* limiting gopem RSA keysize

* fixed service middleware autoref arquitectural problem

* fixing DMS Authorization test

* adding timestamp to logs + newVaultEngine autounseal optional + new ca scan optional

* general fixes

* Update alerts and AWSKMS

* adding cloud hosted DMS

Co-authored-by: Saiz Haritz <hsaiz@ikerlan.es>
Co-authored-by: Ubuntu <ubuntu@ubuntu2110.linuxvmimages.local>
Co-authored-by: Hernandez Elena <Ehernandez@ikerlan.es>
Co-authored-by: jporres <jporres@ikerlan.es>


<a name="0.0.5"></a>
## 0.0.5 (2022-07-20)



### Bug Fixes


* Fixed ca + dev-manager tests

* Fixed release cicd job syntax

* Fix install steps

* Fix install steps

* Fix install steps

* Fix potential EST enroll deserialization error

* Fixed e2e tests

* Fix e2e tests

* Fix db artifacts location

* Fixed certs and domians variables from e2e tests

* Fix unclosed files issue

* Fix clients specs

* Fix est server enroll response

* Fix potential typo

* Fix curl enroll test sh command

* Fix docker image typo

* Fix ca unused import



### Tests


* Testing cicd

* Testing runners

* Testing with running server

* Test monitoring stack

* Testing concurrency

* Testing go installation on ec2

* Testing trivyscan

* Testing trivyscan

* Testing trivyscan

* Testing trivyscan



### Other


* First commit merging individual repos

* Removing cicd self hosted runners

* Added missing runs-on

* Fixed unit tests

* Creating first release

* Reorganized release jobs

* Merge pull request #1 from lamassuiot/develop

fix release cicd job syntax

* Update release.yaml with correct reusable workflow syntax

* Merge branch 'release' of https://github.com/lamassuiot/lamassuiot into release

* Ocsp + various fixes

* Merge branch 'develop' into release

* Fast cicd for testing

* Fast cicd for testing

* Fast cicd for testing

* Fast cicd for testing

* Fast cicd for testing

* Fast cicd for testing

* Fast cicd for testing

* Fast cicd for testing

* Reorganized release jobs

* Extracting IP from cdk deploy

* Extracting IP from cdk deploy

* Extracting IP from cdk deploy

* Extracting IP from cdk deploy

* Extracting IP from cdk deploy

* Extracting IP from cdk deploy

* Ssh test

* Ssh test

* Ssh test

* Ssh test

* Full cicd

* Added dockerfile

* Ocsp test + relase worflow

* Update README.md

* Merge branch 'develop' of https://github.com/lamassuiot/lamassuiot into develop

* Update release.yaml

* Added teardown infra

* New stage

* New stage

* New stage

* New stage

* New stage

* New stage

* New stage

* New stage

* Merge branch 'release' of https://github.com/lamassuiot/lamassuiot into release

* Comment temporal steps

* Revert to full cicd

* Cicd

* Adding full in-memory test

* Added full server testing schema

* Merge branch 'develop' of https://github.com/lamassuiot/lamassuiot into develop

* Refacotred logging system + removed manual span dev

* Merge branch 'develop' of https://github.com/lamassuiot/lamassuiot into develop

* Added CA testing full server

* Added OCSP and EST test to CICD

* Reload profil.d script for go executable

* Install go using user data

* Install go using user data

* Install go using user data

* Install go using user data

* Install go using user data

* Install go using user data

* Install go using user data

* Install go using user data

* Install go using user data

* Added stats endpoint

* Refactoring Structs

* Pre 1.8

* Update filters

* Device-manager test

* CA and DMS enroller tests

* Merge branch 'develop' of https://github.com/lamassuiot/lamassuiot into develop

* Fix logo link

* Add links to docs and lamassu-compose

* Device-manager test

* Resolved  conflicts

* Filters Update

* Update Test

* CA Pagination

* Update CA Test

* Update Workflows

* Update Device Manager Test

* Update e2e Test

* Update Est Test

* Update Est Test

* Remove coverage report from source

* Merge branch 'develop' of https://github.com/lamassuiot/lamassuiot into develop

* Fixed Device Manager Tests

* Fixed DMS Enroller Tests

* Fixed OCSP Tests

* Update release.yml

* Update release.yml

* Update release.yml

* Update Go Version

* DMS Enroller filter

* Merge branch 'develop' of https://github.com/lamassuiot/lamassuiot into develop

* DMS Pagination

* Update DMS Test

* Merge branch 'develop' into release

* Update release.yml

* Update release.yml

* Update release.yml

* Update Performance Test

* Update release.yml

* Merge branch 'develop' of https://github.com/lamassuiot/lamassuiot into develop

* Merge branch 'develop' of https://github.com/lamassuiot/lamassuiot into develop

* Merge branch 'develop' of https://github.com/lamassuiot/lamassuiot into develop

* Merge branch 'develop' of https://github.com/lamassuiot/lamassuiot into develop

* Merge branch 'develop' of https://github.com/lamassuiot/lamassuiot into develop

* Added master worflow

* Merge branch 'develop' of https://github.com/lamassuiot/lamassuiot into develop

* Merge branch 'develop' into release

* First master release

* Workflow rename

* Workflow tags

* Update lamassuiot

* Merge branch 'develop' into release

* Update Device manager

* Merge branch 'develop' into release

* Update go.mod

* Merge branch 'develop' into release

* Update CA main

* Merge branch 'develop' into release

* Merge branch 'release'

* Renamed branch master -> main

* Update device manager and swagger

* Merge branch 'develop' into release

* Update Device manager

* Update Device manager

* Merge branch 'release' of https://github.com/lamassuiot/lamassuiot into release

* Update go.mod

* Renamed expiration log

* Added info endpoint

* Merge pull request #4 from lamassuiot/release

Release


