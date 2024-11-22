
<a name="3.0.0"></a>
## [3.0.0](https://github.com/lamassuiot/lamassuiot/compare/v2.8.0...3.0.0) (2024-11-22)

### Chores

* Chore: fix awsconnector dockerfile
* Chore: ci update dockerfiles and gh workflow ([#177](https://github.com/lamassuiot/lamassuiot/issues/177))

### Refactor

* Refactor: major refactor v3 pakage - structured code into go submodules([#176](https://github.com/lamassuiot/lamassuiot/issues/176))


<a name="v2.8.0"></a>
## [v2.8.0](https://github.com/lamassuiot/lamassuiot/compare/v2.7.0...v2.8.0) (2024-10-25)

### Bug Fixes

* Fix: Alerts: add missing SMTP config to service builder ([#168](https://github.com/lamassuiot/lamassuiot/issues/168))

### Chores

* Chore: move mapstructure unmantained depency to new ref

### Features

* Feat: DMS: Allow enrollment with expired certificates ([#171](https://github.com/lamassuiot/lamassuiot/issues/171))
* Feat: AWS IoT Connector: Add additional info in CA registration mode + add SNI CA registration (without private key access) ([#166](https://github.com/lamassuiot/lamassuiot/issues/166))

### Test

* Test: Allow importing SQL dumps into DBs in docker-launched postgres container ([#170](https://github.com/lamassuiot/lamassuiot/issues/170))
* Test: DMS Manager: add new test to the EST routes and controller ([#169](https://github.com/lamassuiot/lamassuiot/issues/169))


<a name="v2.7.0"></a>
## [v2.7.0](https://github.com/lamassuiot/lamassuiot/compare/v2.6.0...v2.7.0) (2024-10-02)

### Chores

* Chore: fix ci release workflow
* Chore: Add dependant job in release workflow ([#167](https://github.com/lamassuiot/lamassuiot/issues/167))
* Chore: Add changelog generation based on commits ([#158](https://github.com/lamassuiot/lamassuiot/issues/158))

### Feat

* Feat: AWS Connector: Improve event description in Device's Events on shadow update ([#157](https://github.com/lamassuiot/lamassuiot/issues/157))
* Feat: DMS Manager Add support for EST ServerKeyGen ([#123](https://github.com/lamassuiot/lamassuiot/issues/123))
* Feat: reduce erroneous event processing Intervals in eventbus([#165](https://github.com/lamassuiot/lamassuiot/issues/165))
* Feat: allow multiple AWS Connectors in a single Lamassu Instance
* Feat: Add support for Nginx client certificate identity extraction ([#161](https://github.com/lamassuiot/lamassuiot/issues/161))


<a name="v2.6.0"></a>
## [v2.6.0](https://github.com/lamassuiot/lamassuiot/compare/v2.5.3...v2.6.0) (2024-08-31)

### Features

* Feat: AWS Connector: Handle update certificate status & disconnect things from IoTCore on revoke ([#159](https://github.com/lamassuiot/lamassuiot/issues/159))


<a name="v2.5.3"></a>
## [v2.5.3](https://github.com/lamassuiot/lamassuiot/compare/v2.5.2...v2.5.3) (2024-07-16)


<a name="v2.5.2"></a>
## [v2.5.2](https://github.com/lamassuiot/lamassuiot/compare/v2.5.1...v2.5.2) (2024-06-21)

### Chores

* Chore: customize codecov integration ([#133](https://github.com/lamassuiot/lamassuiot/issues/133))
* Chore: remove unused swagger support ([#118](https://github.com/lamassuiot/lamassuiot/issues/118))

### Refactor

* Refactor: Make event handlers first-class citizens in our code ([#121](https://github.com/lamassuiot/lamassuiot/issues/121))

### Tests

* Test: Refactor to start event buses once during tests ([#141](https://github.com/lamassuiot/lamassuiot/issues/141))
* Test: add mock based test to event publisher middelwares  ([#120](https://github.com/lamassuiot/lamassuiot/issues/120))


<a name="v2.5.1"></a>
## [v2.5.1](https://github.com/lamassuiot/lamassuiot/compare/v2.5.0...v2.5.1) (2024-05-09)

### Test

* Test: config loader tests


<a name="v2.5.0"></a>
## [v2.5.0](https://github.com/lamassuiot/lamassuiot/compare/v2.4.6...v2.5.0) (2024-02-22)


<a name="v2.4.6"></a>
## [v2.4.6](https://github.com/lamassuiot/lamassuiot/compare/v2.4.5...v2.4.6) (2024-02-13)


<a name="v2.4.5"></a>
## [v2.4.5](https://github.com/lamassuiot/lamassuiot/compare/v2.4.4...v2.4.5) (2024-02-10)


<a name="v2.4.4"></a>
## [v2.4.4](https://github.com/lamassuiot/lamassuiot/compare/v2.4.3...v2.4.4) (2024-02-05)


<a name="v2.4.3"></a>
## [v2.4.3](https://github.com/lamassuiot/lamassuiot/compare/v2.4.2...v2.4.3) (2024-01-31)


<a name="v2.4.2"></a>
## [v2.4.2](https://github.com/lamassuiot/lamassuiot/compare/v2.4.1...v2.4.2) (2024-01-30)


<a name="v2.4.1"></a>
## [v2.4.1](https://github.com/lamassuiot/lamassuiot/compare/v2.4.0...v2.4.1) (2023-12-22)


<a name="v2.4.0"></a>
## [v2.4.0](https://github.com/lamassuiot/lamassuiot/compare/v2.0.0...v2.4.0) (2023-12-20)


<a name="v2.0.0"></a>
## [v2.0.0](https://github.com/lamassuiot/lamassuiot/compare/v1.1.0...v2.0.0) (2023-01-13)


<a name="v1.1.0"></a>
## v1.1.0 (2022-07-20)

### Pull Requests

* Merge pull request [#4](https://github.com/lamassuiot/lamassuiot/issues/4) from lamassuiot/release
* Merge pull request [#1](https://github.com/lamassuiot/lamassuiot/issues/1) from lamassuiot/develop

