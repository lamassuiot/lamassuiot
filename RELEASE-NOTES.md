
<a name="3.5.0"></a>
## [3.5.0](https://github.com/lamassuiot/lamassuiot/compare/engines/eventbus/aws/v3.4.0...3.5.0) (2025-09-23)

### Bug Fixes

* Fix: ca: SKI and AKI extracrted from certificates (if any) ([#295](https://github.com/lamassuiot/lamassuiot/issues/295))
* Fix: add dlq to event bus after 3 retries ([#302](https://github.com/lamassuiot/lamassuiot/issues/302))
* Fix: allow signing certs expiring after ca ([#299](https://github.com/lamassuiot/lamassuiot/issues/299))
* Fix: middleware: missing DeleteDevice operation
* Fix: ca: fix crl urls in generated certificates to include hex encoded with colons ([#279](https://github.com/lamassuiot/lamassuiot/issues/279))
* Fix: no tmp_dir for fileblob persistence ([#277](https://github.com/lamassuiot/lamassuiot/issues/277))
* Fix: CRL Initialization on event ([#273](https://github.com/lamassuiot/lamassuiot/issues/273))
* Fix: update bookmark encoding to use URL-safe base64 encoding ([#272](https://github.com/lamassuiot/lamassuiot/issues/272))

### Chores

* Chore: refactoring release process ([#304](https://github.com/lamassuiot/lamassuiot/issues/304))
* Chore: update CONTRIBUTING.md to clarify setup instructions ([#296](https://github.com/lamassuiot/lamassuiot/issues/296))
* Chore: fix linting and typo issues ([#287](https://github.com/lamassuiot/lamassuiot/issues/287))
* Chore: monolithic: add labels and standard ports in docker containers ([#281](https://github.com/lamassuiot/lamassuiot/issues/281))
* Chore: Bump dependencies ([#278](https://github.com/lamassuiot/lamassuiot/issues/278))

### Features

* Feat: add DELETE certificate endpoint for orphaned certificate cleanup with issuer CA validation ([#301](https://github.com/lamassuiot/lamassuiot/issues/301))
* Feat: add support for filtering CAs based on profile_id ([#303](https://github.com/lamassuiot/lamassuiot/issues/303))
* Feat: all: add audit events ([#291](https://github.com/lamassuiot/lamassuiot/issues/291))
* Feat: va: add support for CRL certificate reactivation from hold  ([#297](https://github.com/lamassuiot/lamassuiot/issues/297))
* Feat: add support for deleting devices in decommissioned state ([#294](https://github.com/lamassuiot/lamassuiot/issues/294))
* Feat: ca: avoid redundancy on issuance profiles generation ([#292](https://github.com/lamassuiot/lamassuiot/issues/292))
* Feat: ca: default issuance profiles for CAs and integrate in dms EST processes ([#290](https://github.com/lamassuiot/lamassuiot/issues/290))
* Feat: CA: Add Full CRUD Support for Issuance Profiles in CA Service ([#286](https://github.com/lamassuiot/lamassuiot/issues/286))
* Feat: add PATCH method to metadata endpoints ([#284](https://github.com/lamassuiot/lamassuiot/issues/284))
* Feat: DMS: implement update metadata endpoint ([#283](https://github.com/lamassuiot/lamassuiot/issues/283))
* Feat: va: Remove get roles ([#280](https://github.com/lamassuiot/lamassuiot/issues/280))
* Feat: DMS: add certificate Issuance Profile support ([#276](https://github.com/lamassuiot/lamassuiot/issues/276))
* Feat: refactor by adding InitCRLRole method to CRLService and its implementations ([#271](https://github.com/lamassuiot/lamassuiot/issues/271))
* Feat: add case-insensitive filtering support ([#270](https://github.com/lamassuiot/lamassuiot/issues/270))
* Feat: DMS Manager: add option to toggle CSR signature verification during Enrollment/Reenrollment ([#268](https://github.com/lamassuiot/lamassuiot/issues/268))

### Refactor

* Refactor: CA: homogenize certificate SN format ([#289](https://github.com/lamassuiot/lamassuiot/issues/289))

### Tests

* Test: middleware: add DeleteDevice case to event publisher ([#298](https://github.com/lamassuiot/lamassuiot/issues/298))

