
<a name="3.4.0"></a>
## [3.4.0](https://github.com/lamassuiot/lamassuiot/compare/connectors/awsiot/v3.3.0...3.4.0) (2025-06-03)

### Bug Fixes

* Fix: CA:  fix filtering CAs by CN ([#265](https://github.com/lamassuiot/lamassuiot/issues/265))
* Fix: CA: discard aws reserved kms aliases ([#266](https://github.com/lamassuiot/lamassuiot/issues/266))
* Fix: DMS Manager: ReEnroll - Add a check to validate the presence of a CommonName in the CSR ([#251](https://github.com/lamassuiot/lamassuiot/issues/251))
* Fix: DMS Manager: add a null check when decommissioning a device wihtout identity ([#250](https://github.com/lamassuiot/lamassuiot/issues/250))
* Fix: monolithic ui port now being served correctly ([#240](https://github.com/lamassuiot/lamassuiot/issues/240))

### Bump Versions

* Bump: backend direct deps ([#264](https://github.com/lamassuiot/lamassuiot/issues/264))
* Bump: go-jose to 4.0.5 ([#263](https://github.com/lamassuiot/lamassuiot/issues/263))

### Chores

* Chore: bump x/net to 0.38.0 ([#262](https://github.com/lamassuiot/lamassuiot/issues/262))
* Chore: bump go-playground/validator to v10.26.0 ([#261](https://github.com/lamassuiot/lamassuiot/issues/261))
* Chore: bump aws sdk 1.36.3 ([#260](https://github.com/lamassuiot/lamassuiot/issues/260))
* Chore: bump ory/dockertest 3.12.0 ([#259](https://github.com/lamassuiot/lamassuiot/issues/259))
* Chore: Bump golang-jwt to 4.5.2 ([#258](https://github.com/lamassuiot/lamassuiot/issues/258))
* Chore: bumping go version 1.24 ([#255](https://github.com/lamassuiot/lamassuiot/issues/255))
* Chore: adjust monolithic monitoring job ([#239](https://github.com/lamassuiot/lamassuiot/issues/239))

### Features

* Feat: DMS Manager: add DMS delete operation ([#252](https://github.com/lamassuiot/lamassuiot/issues/252))
* Feat: CA: implement AWS KMS import keys ([#245](https://github.com/lamassuiot/lamassuiot/issues/245))
* Feat: CA: refactor crypto engine keys migration ([#246](https://github.com/lamassuiot/lamassuiot/issues/246))
* Feat: VA: assemble service conditionally based on config ([#244](https://github.com/lamassuiot/lamassuiot/issues/244))
* Feat: enhance event filters to use full event data for processing ([#242](https://github.com/lamassuiot/lamassuiot/issues/242))

