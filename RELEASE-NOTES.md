
<a name="3.7.0"></a>
## [3.7.0](https://github.com/lamassuiot/lamassuiot/compare/engines/fs-storage/localfs/v3.6.3...3.7.0) (2026-01-29)

### Bug Fixes

* Fix: ca:  Root CA Extended Key Usages ([#370](https://github.com/lamassuiot/lamassuiot/issues/370))

### Chores

* Chore: Add JSON Patch support documentation (RFC 6902) ([#379](https://github.com/lamassuiot/lamassuiot/issues/379))
* Chore: openapi -  standardize authentication schemes  ([#372](https://github.com/lamassuiot/lamassuiot/issues/372))
* Chore: Go dependency cleanup ([#364](https://github.com/lamassuiot/lamassuiot/issues/364))
* Chore: Add OpenAPI specifications for all APIs ([#363](https://github.com/lamassuiot/lamassuiot/issues/363))

### Features

* Feat: add lamassu-db-migration Dockerfile and update references in workflows and README ([#383](https://github.com/lamassuiot/lamassuiot/issues/383))
* Feat: support sort using jsonpath expressions ([#381](https://github.com/lamassuiot/lamassuiot/issues/381))
* Feat: migrate metadata columns to JSONB and add JSONPath filtering ([#378](https://github.com/lamassuiot/lamassuiot/issues/378))
* Feat: Implement CA reissuance functionality ([#357](https://github.com/lamassuiot/lamassuiot/issues/357))
* Feat: add expiration date info for device identity slots ([#377](https://github.com/lamassuiot/lamassuiot/issues/377))
* Feat: implement device filtering statistics functionality ([#376](https://github.com/lamassuiot/lamassuiot/issues/376))
* Feat: enable Docker-less local development via SQLite storage and In-Memory bus ([#374](https://github.com/lamassuiot/lamassuiot/issues/374))
* Feat: add CA issuance profile support for CreateCA functionality ([#371](https://github.com/lamassuiot/lamassuiot/issues/371))

### Refactor

* Refactor: Isolate backend assembler tests for better coverage and optimize CI timeouts ([#365](https://github.com/lamassuiot/lamassuiot/issues/365))
* Refactor: CA Service to External KMS ([#350](https://github.com/lamassuiot/lamassuiot/issues/350))

