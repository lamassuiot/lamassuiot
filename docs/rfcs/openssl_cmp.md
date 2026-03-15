➜ openssl cmp -h
cmp_main:apps/cmp.c:3686:CMP info: using section(s) 'cmp' of OpenSSL configuration file '/home/linuxbrew/.linuxbrew/etc/openssl@3/openssl.cnf'
cmp_main:apps/cmp.c:3694:CMP info: no [cmp] section found in config file '/home/linuxbrew/.linuxbrew/etc/openssl@3/openssl.cnf'; will thus use just [default] and unnamed section if present
Usage: cmp [options]
Valid options are:
 -help                  Display this summary
 -config val            Configuration file to use. "" = none. Default from env variable OPENSSL_CONF
 -section val           Section(s) in config file to get options from. "" = 'default'. Default 'cmp'
 -verbosity nonneg      Log level; 3=ERR, 4=WARN, 6=INFO, 7=DEBUG, 8=TRACE. Default 6 = INFO

Generic message options:
 -cmd val               CMP request to send: ir/cr/kur/p10cr/rr/genm
 -infotype val          InfoType name for requesting specific info in genm, with specific support
                        for 'caCerts' and 'rootCaCert'
 -profile val           Certificate profile name to place in generalInfo field of request PKIHeader
 -geninfo val           Comma-separated list of OID and value to place in generalInfo PKIHeader
                        of form <OID>:int:<n> or <OID>:str:<s>, e.g. '1.2.3.4:int:56789, id-kp:str:name'
 -template val          File to save certTemplate received in genp of type certReqTemplate
 -keyspec val           Optional file to save Key specification received in genp of type certReqTemplate

Certificate enrollment options:
 -newkey val            Private or public key for the requested cert. Default: CSR key or client key
 -newkeypass val        New private key pass phrase source
 -centralkeygen         Request central (server-side) key generation. Default is local generation
 -newkeyout val         File to save centrally generated key, in PEM format
 -subject val           Distinguished Name (DN) of subject to use in the requested cert template
                        For kur, default is subject of -csr arg or reference cert (see -oldcert)
                        this default is used for ir and cr only if no Subject Alt Names are set
 -days nonneg           Requested validity time of the new certificate in number of days
 -reqexts val           Name of config file section defining certificate request extensions.
                        Augments or replaces any extensions contained CSR given with -csr
 -sans val              Subject Alt Names (IPADDR/DNS/URI) to add as (critical) cert req extension
 -san_nodefault         Do not take default SANs from reference certificate (see -oldcert)
 -policies val          Name of config file section defining policies certificate request extension
 -policy_oids val       Policy OID(s) to add as policies certificate request extension
 -policy_oids_critical  Flag the policy OID(s) given with -policy_oids as critical
 -popo int              Proof-of-Possession (POPO) method to use for ir/cr/kur where
                        -1 = NONE, 0 = RAVERIFIED, 1 = SIGNATURE (default), 2 = KEYENC
 -csr val               PKCS#10 CSR file in PEM or DER format to convert or to use in p10cr
 -out_trusted val       Certificates to trust when verifying newly enrolled certificates
 -implicit_confirm      Request implicit confirmation of newly enrolled certificates
 -disable_confirm       Do not confirm newly enrolled certificate w/o requesting implicit
                        confirmation. WARNING: This leads to behavior violating RFC 9810
 -certout val           File to save newly enrolled certificate
 -chainout val          File to save the chain of newly enrolled certificate

Certificate enrollment and revocation options:
 -oldcert val           Certificate to be updated (defaulting to -cert) or to be revoked in rr;
                        also used as reference (defaulting to -cert) for subject DN and SANs.
                        Issuer is used as recipient unless -recipient, -srvcert, or -issuer given
 -issuer val            DN of the issuer to place in the certificate template of ir/cr/kur/rr;
                        also used as recipient if neither -recipient nor -srvcert are given
 -serial val            Serial number of certificate to be revoked in revocation request (rr)
 -revreason int         Reason code to include in revocation request (rr); possible values:
                        0..6, 8..10 (see RFC5280, 5.3.1) or -1. Default -1 = none included

Message transfer options:
 -server val            [http[s]://]address[:port][/path] of CMP server. Default port 80 or 443.
                        address may be a DNS name or an IP address; path can be overridden by -path
 -proxy val             [http[s]://]address[:port][/path] of HTTP(S) proxy to use; path is ignored
 -no_proxy val          List of addresses of servers not to use HTTP(S) proxy for
                        Default from environment variable 'no_proxy', else 'NO_PROXY', else none
 -recipient val         DN of CA. Default: subject of -srvcert, -issuer, issuer of -oldcert or -cert
 -path val              HTTP path (aka CMP alias) at the CMP server. Default from -server, else "/"
 -keep_alive nonneg     Persistent HTTP connections. 0: no, 1 (the default): request, 2: require
 -msg_timeout nonneg    Number of seconds allowed per CMP message round trip, or 0 for infinite
 -total_timeout nonneg  Overall time an enrollment incl. polling may take. Default 0 = infinite

Server authentication options:
 -trusted val           Certificates to use as trust anchors when verifying signed CMP responses
                        unless -srvcert is given
 -untrusted val         Intermediate CA certs for chain construction for CMP/TLS/enrolled certs
 -srvcert val           Server cert to pin and trust directly when verifying signed CMP responses
 -expect_sender val     DN of expected sender of responses. Defaults to subject of -srvcert, if any
 -ignore_keyusage       Ignore CMP signer cert key usage, else 'digitalSignature' must be allowed
 -unprotected_errors    Accept missing or invalid protection of regular error messages and negative
                        certificate responses (ip/cp/kup), revocation responses (rp), and PKIConf
                        WARNING: This setting leads to behavior allowing violation of RFC 9810
 -no_cache_extracerts   Do not keep certificates received in the extraCerts CMP message field
 -srvcertout val        File to save the server cert used and validated for CMP response protection
 -extracertsout val     File to save extra certificates received in the extraCerts field
 -cacertsout val        File to save CA certs received in caPubs field or genp with id-it-caCerts
 -oldwithold val        Root CA certificate to request update for in genm of type rootCaCert
 -newwithnew val        File to save NewWithNew cert received in genp of type rootCaKeyUpdate
 -newwithold val        File to save NewWithOld cert received in genp of type rootCaKeyUpdate
 -oldwithnew val        File to save OldWithNew cert received in genp of type rootCaKeyUpdate
 -crlcert val           certificate to request a CRL for in genm of type crlStatusList
 -oldcrl val            CRL to request update for in genm of type crlStatusList
 -crlout val            File to save new CRL received in genp of type 'crls'

Client authentication options:
 -ref val               Reference value to use as senderKID in case no -cert is given
 -secret val            Prefer PBM (over signatures) for protecting msgs with given password source
 -cert val              Client's CMP signer certificate; its public key must match the -key argument
                        This also used as default reference for subject DN and SANs.
                        Any further certs included are appended to the untrusted certs
 -own_trusted val       Optional certs to verify chain building for own CMP signer cert
 -key val               CMP signer private key, not used when -secret given
 -keypass val           Client private key (and cert and old cert) pass phrase source
 -digest val            Digest to use in message protection and POPO signatures. Default "sha256"
 -mac val               MAC algorithm to use in PBM-based message protection. Default "hmac-sha1"
 -extracerts val        Certificates to append in extraCerts field of outgoing messages.
                        This can be used as the default CMP signer cert chain to include
 -unprotected_requests  Send request messages without CMP-level protection

Credentials format options:
 -certform val          Format (PEM or DER) to use when saving a certificate to a file. Default PEM
 -crlform val           Format (PEM or DER) to use when saving a CRL to a file. Default DER
 -keyform val           Format of the key input (ENGINE, other values ignored)
 -otherpass val         Pass phrase source potentially needed for loading certificates of others
 -engine val            Use crypto engine with given identifier, possibly a hardware device.
                        Engines may also be defined in OpenSSL config file engine section.

Provider options:
 -provider-path val     Provider load path (must be before 'provider' argument if required)
 -provider val          Provider to load (can be specified multiple times)
 -provparam val         Set a provider key-value parameter
 -propquery val         Property query used when fetching algorithms

Random state options:
 -rand val              Load the given file(s) into the random number generator
 -writerand outfile     Write random data to the specified file

TLS connection options:
 -tls_used              Enable using TLS (also when other TLS options are not set)
 -tls_cert val          Client's TLS certificate. May include chain to be provided to TLS server
 -tls_key val           Private key for the client's TLS certificate
 -tls_keypass val       Pass phrase source for the client's private TLS key (and TLS cert)
 -tls_extra val         Extra certificates to provide to TLS server during TLS handshake
 -tls_trusted val       Trusted certificates to use for verifying the TLS server certificate;
                        this implies hostname validation
 -tls_host val          Address to be checked (rather than -server) during TLS hostname validation

Client-side debugging options:
 -batch                 Do not interactively prompt for input when a password is required etc.
 -repeat +int           Invoke the transaction the given positive number of times. Default 1
 -reqin val             Take sequence of CMP requests to send to server from file(s)
 -reqin_new_tid         Use fresh transactionID for CMP requests read from -reqin
 -reqout val            Save sequence of CMP requests created by the client to file(s)
 -reqout_only val       Save first CMP request created by the client to file and exit
 -rspin val             Process sequence of CMP responses provided in file(s), skipping server
 -rspout val            Save sequence of actually used CMP responses to file(s)
 -use_mock_srv          Use internal mock server at API level, bypassing socket-based HTTP

Mock server options:
 -port val              Act as HTTP-based mock server listening on given port
 -max_msgs nonneg       max number of messages handled by HTTP mock server. Default: 0 = unlimited
 -srv_ref val           Reference value to use as senderKID of server in case no -srv_cert is given
 -srv_secret val        Password source for server authentication with a pre-shared key (secret)
 -srv_cert val          Certificate of the server
 -srv_key val           Private key used by the server for signing messages
 -srv_keypass val       Server private key (and cert) pass phrase source
 -srv_trusted val       Trusted certificates for client authentication
 -srv_untrusted val     Intermediate certs that may be useful for verifying CMP protection
 -ref_cert val          Certificate to be expected for rr and any oldCertID in kur messages
 -rsp_cert val          Certificate to be returned as mock enrollment result
 -rsp_key val           Private key for the certificate to be returned as mock enrollment result
                        Key to be returned for central key pair generation
 -rsp_keypass val       Response private key (and cert) pass phrase source
 -rsp_crl val           CRL to be returned in genp of type crls
 -rsp_extracerts val    Extra certificates to be included in mock certification responses
 -rsp_capubs val        CA certificates to be included in mock ip response
 -rsp_newwithnew val    New root CA certificate to include in genp of type rootCaKeyUpdate
 -rsp_newwithold val    NewWithOld transition cert to include in genp of type rootCaKeyUpdate
 -rsp_oldwithnew val    OldWithNew transition cert to include in genp of type rootCaKeyUpdate
 -poll_count nonneg     Number of times the client must poll before receiving a certificate
 -check_after nonneg    The check_after value (time to wait) to include in poll response
 -grant_implicitconf    Grant implicit confirmation of newly enrolled certificate
 -pkistatus nonneg      PKIStatus to be included in server response. Possible values: 0..6
 -failure nonneg        A single failure info bit number to include in server response, 0..26
 -failurebits nonneg    Number representing failure bits to include in server response, 0..2^27 - 1
 -statusstring val      Status string to be included in server response
 -send_error            Force server to reply with error message
 -send_unprotected      Send response messages without CMP-level protection
 -send_unprot_err       In case of negative responses, server shall send unprotected error messages,
                        certificate responses (ip/cp/kup), and revocation responses (rp).
                        WARNING: This setting leads to behavior violating RFC 9810
 -accept_unprotected    Accept missing or invalid protection of requests
 -accept_unprot_err     Accept unprotected error messages from client
 -accept_raverified     Accept RAVERIFIED as proof-of-possession (POPO)

Validation options:
 -policy val            adds policy to the acceptable policy set
 -purpose val           certificate chain purpose
 -verify_name val       verification policy name
 -verify_depth int      chain depth limit
 -auth_level int        chain authentication security level
 -attime intmax         verification epoch time
 -verify_hostname val   expected peer hostname
 -verify_email val      expected peer email
 -verify_ip val         expected peer IP address
 -ignore_critical       permit unhandled critical extensions
 -issuer_checks         (deprecated)
 -crl_check             check leaf certificate revocation
 -crl_check_all         check full chain revocation
 -policy_check          perform rfc5280 policy checks
 -explicit_policy       set policy variable require-explicit-policy
 -inhibit_any           set policy variable inhibit-any-policy
 -inhibit_map           set policy variable inhibit-policy-mapping
 -x509_strict           disable certificate compatibility work-arounds
 -extended_crl          enable extended CRL features
 -use_deltas            use delta CRLs
 -policy_print          print policy processing diagnostics
 -check_ss_sig          check root CA self-signatures
 -trusted_first         search trust store first (default)
 -suiteB_128_only       Suite B 128-bit-only mode
 -suiteB_128            Suite B 128-bit mode allowing 192-bit algorithms
 -suiteB_192            Suite B 192-bit-only mode
 -partial_chain         accept chains anchored by intermediate trust-store CAs
 -no_alt_chains         (deprecated)
 -no_check_time         ignore certificate validity time
 -allow_proxy_certs     allow the use of proxy certificates