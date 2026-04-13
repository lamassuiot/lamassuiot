
package policies

############################
# Helpers
############################

trim(x) := y if {
	y := trim_space(sprintf("%v", [x]))
}

normalize(x) := y if {
	x != null
	y := lower(trim(x))
}

name(component) := normalize(object.get(component, "name", ""))

bom_ref(component) := object.get(component, "bom-ref", "")

crypto(component) := object.get(component, "cryptoProperties", {})

alg_props(component) := object.get(crypto(component), "algorithmProperties", {})

proto_props(component) := object.get(crypto(component), "protocolProperties", {})

asset_type(component) := normalize(object.get(crypto(component), "assetType", ""))

primitive(component) := normalize(object.get(alg_props(component), "primitive", ""))

oid(component) := normalize(object.get(crypto(component), "oid", ""))

num(x, dflt) := n if {
	n := to_number(x)
} else := dflt

key_bits(component) := n if {
	n := num(object.get(alg_props(component), "keyLength", null), -1)
	n >= 0
} else := n if {
	n := num(object.get(alg_props(component), "keySize", null), -1)
	n >= 0
} else := n if {
	n := num(object.get(alg_props(component), "length", null), -1)
	n >= 0
} else := -1

hash_bits(component) := n if {
	n := num(object.get(alg_props(component), "outputSize", null), -1)
	n >= 0
} else := n if {
	n := num(object.get(alg_props(component), "hashLength", null), -1)
	n >= 0
} else := -1

modulus_bits(component) := n if {
	n := num(object.get(alg_props(component), "modulusLength", null), -1)
	n >= 0
} else := n if {
	n := num(object.get(alg_props(component), "modulusSize", null), -1)
	n >= 0
} else := -1

subgroup_bits(component) := n if {
	n := num(object.get(alg_props(component), "subgroupSize", null), -1)
	n >= 0
} else := n if {
	n := num(object.get(alg_props(component), "qLength", null), -1)
	n >= 0
} else := -1

public_exponent_bits(component) := n if {
	n := num(object.get(alg_props(component), "publicExponentLength", null), -1)
	n >= 0
} else := -1

curve_name(component) := normalize(
	object.get(
		alg_props(component),
		"curve",
		object.get(crypto(component), "curve", "")
	)
)

tls_version(component) := normalize(
	object.get(
		proto_props(component),
		"version",
		object.get(crypto(component), "protocolVersion", "")
	)
)

tls_cipher_suite(component) := normalize(
	object.get(
		proto_props(component),
		"cipherSuite",
		object.get(crypto(component), "cipherSuite", "")
	)
)

status_to_result(status) := "quantum-safe" if {
	status == "recommended"
} else := "quantum-safe" if {
	status == "legacy"
} else := "quantum-vulnerable" if {
	status == "not-agreed"
} else := "NA" if {
	status == "na"
} else := "unknown"

mk_finding(component, rule, status, property, value) := {
	"bom-ref": bom_ref(component),
	"rule": rule,
	"result": status_to_result(status),
	"eccg_status": status,
	"property": property,
	"value": value,
}

############################
# Classification helpers
############################

is_crypto_asset(component) if {
	asset_type(component) == "cryptographic-asset"
}

is_algorithm(component) if {
	is_crypto_asset(component)
}

is_tls(component) if {
	tls_version(component) != ""
}

is_tls(component) if {
	contains(name(component), "tls")
}

is_aes_name(n) if {
	n == "aes"
}

is_aes_name(n) if {
	contains(n, "aes-")
}

is_3des_name(n) if {
	n == "triple-des"
}

is_3des_name(n) if {
	n == "3des"
}

is_3des_name(n) if {
	contains(n, "des-ede3")
}

is_rsa_name(n) if {
	n == "rsa"
}

is_rsa_name(n) if {
	contains(n, "rsa")
}

is_rsa_oaep_name(n) if {
	n == "rsa-oaep"
}

is_rsa_oaep_name(n) if {
	contains(n, "oaep")
}

is_rsa_pkcs1_v15_name(n) if {
	n == "rsa-pkcs1v1.5"
}

is_rsa_pkcs1_v15_name(n) if {
	contains(n, "pkcs#1v1.5")
}

is_shamir_name(n) if {
	n == "shamir"
}

is_shamir_name(n) if {
	contains(n, "shamir")
}

is_ffdlog_name(n) if {
	contains(n, "ffdhe")
}

is_ffdlog_name(n) if {
	contains(n, "modp")
}

is_ffdlog_name(n) if {
	contains(n, "dh")
}

is_ffdlog_name(n) if {
	contains(n, "dsa")
}

is_ffdlog_name(n) if {
	contains(n, "schnorr")
}

is_ffdlog_primitive(p) if {
	p == "keyagree"
}

is_ffdlog_primitive(p) if {
	p == "signature"
}

is_ffdlog_primitive(p) if {
	p == "pke"
}

is_sha2_sha3_recommended(n, h) if {
	n == "sha-256"
	h == 256
}

is_sha2_sha3_recommended(n, h) if {
	n == "sha-384"
	h == 384
}

is_sha2_sha3_recommended(n, h) if {
	n == "sha-512"
	h == 512
}

is_sha2_sha3_recommended(n, h) if {
	n == "sha-512/256"
	h == 256
}

is_sha2_sha3_recommended(n, h) if {
	n == "sha3-256"
	h == 256
}

is_sha2_sha3_recommended(n, h) if {
	n == "sha3-384"
	h == 384
}

is_sha2_sha3_recommended(n, h) if {
	n == "sha3-512"
	h == 512
}

is_sha_legacy(n, h) if {
	n == "sha-224"
	h == 224
}

is_sha_legacy(n, h) if {
	n == "sha-512/224"
	h == 224
}

############################
# ECCG v2 algorithm status
############################

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "keyLength",
	"value": key_bits(component),
	"ref": "AES k in {128,192,256}",
} if {
	n := name(component)
	is_aes_name(n)
	key_bits(component) in {128, 192, 256}
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "keyLength",
	"value": key_bits(component),
	"ref": "3DES k=168",
} if {
	n := name(component)
	is_3des_name(n)
	key_bits(component) == 168
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "hashLength",
	"value": hash_bits(component),
	"ref": "SHA-2/SHA-3 agreed",
} if {
	n := name(component)
	h := hash_bits(component)
	is_sha2_sha3_recommended(n, h)
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "hashLength",
	"value": hash_bits(component),
	"ref": "SHA-224 / SHA-512/224 legacy [2025]",
} if {
	n := name(component)
	h := hash_bits(component)
	is_sha_legacy(n, h)
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "name",
	"value": name(component),
	"ref": "Shamir secret sharing",
} if {
	n := name(component)
	is_shamir_name(n)
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "name",
	"value": name(component),
	"ref": "CMAC / CBC-MAC / GMAC",
} if {
	name(component) in {"cmac", "cbc-mac", "gmac"}
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "keyLength",
	"value": key_bits(component),
	"ref": "HMAC k>=125",
} if {
	name(component) == "hmac"
	key_bits(component) >= 125
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "keyLength",
	"value": key_bits(component),
	"ref": "HMAC 100<=k<125",
} if {
	name(component) == "hmac"
	key_bits(component) >= 100
	key_bits(component) < 125
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "keyLength",
	"value": key_bits(component),
	"ref": "HMAC-SHA-1 k>=100 legacy [2030]",
} if {
	n := name(component)
	n in {"hmac-sha-1", "hmac-sha1"}
	key_bits(component) >= 100
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "keyLength",
	"value": key_bits(component),
	"ref": "KMAC128 k>=125",
} if {
	name(component) == "kmac128"
	key_bits(component) >= 125
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "keyLength",
	"value": key_bits(component),
	"ref": "KMAC256 k>=250",
} if {
	name(component) == "kmac256"
	key_bits(component) >= 250
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "name",
	"value": name(component),
	"ref": "Agreed symmetric constructions",
} if {
	name(component) in {
		"encrypt-then-mac",
		"ccm",
		"gcm",
		"eax",
		"siv",
		"aes-keywrap",
		"aes-kw",
		"aes-kwp",
		"ansi-x9.63-kdf",
		"hkdf",
		"pbkdf2",
		"catkdf",
		"caskdf",
		"xts",
	}
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "name",
	"value": name(component),
	"ref": "MAC-then-Encrypt / Encrypt-and-MAC legacy [2025]",
} if {
	name(component) in {"mac-then-encrypt", "encrypt-and-mac", "cbc-essiv"}
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "modulusLength",
	"value": modulus_bits(component),
	"ref": "RSA n>=3000 and log2(e)>16",
} if {
	n := name(component)
	is_rsa_name(n)
	modulus_bits(component) >= 3000
	public_exponent_bits(component) > 16
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "modulusLength",
	"value": modulus_bits(component),
	"ref": "RSA 1900<=n<3000 and log2(e)>16 legacy [2025]",
} if {
	n := name(component)
	is_rsa_name(n)
	modulus_bits(component) >= 1900
	modulus_bits(component) < 3000
	public_exponent_bits(component) > 16
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "modulusLength",
	"value": {"p": modulus_bits(component), "q": subgroup_bits(component)},
	"ref": "FF-DLOG p>=3000 q>=250",
} if {
	p := primitive(component)
	is_ffdlog_primitive(p)
	n := name(component)
	is_ffdlog_name(n)
	modulus_bits(component) >= 3000
	subgroup_bits(component) >= 250
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "modulusLength",
	"value": {"p": modulus_bits(component), "q": subgroup_bits(component)},
	"ref": "FF-DLOG p>=1900 q>=200 legacy [2025]",
} if {
	p := primitive(component)
	is_ffdlog_primitive(p)
	n := name(component)
	is_ffdlog_name(n)
	modulus_bits(component) >= 1900
	modulus_bits(component) < 3000
	subgroup_bits(component) >= 200
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "name",
	"value": name(component),
	"ref": "MODP/FFDHE 3072+",
} if {
	n := name(component)
	n in {
		"3072-bit modp group",
		"4096-bit modp group",
		"6144-bit modp group",
		"8192-bit modp group",
		"3072-bit ffdhe group",
		"4096-bit ffdhe group",
		"6144-bit ffdhe group",
		"8192-bit ffdhe group",
	}
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "name",
	"value": name(component),
	"ref": "2048-bit MODP/FFDHE legacy [2025]",
} if {
	n := name(component)
	n in {"2048-bit modp group", "2048-bit ffdhe group"}
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "curve",
	"value": curve_name(component),
	"ref": "Agreed ECC curves",
} if {
	curve_name(component) in {
		"brainpoolp256r1",
		"brainpoolp384r1",
		"brainpoolp512r1",
		"nist p-256",
		"nist p-384",
		"nist p-521",
		"p-256",
		"p-384",
		"p-521",
		"frp256v1",
	}
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "name",
	"value": name(component),
	"ref": "RSA-OAEP",
} if {
	n := name(component)
	is_rsa_oaep_name(n)
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "name",
	"value": name(component),
	"ref": "RSA PKCS#1 v1.5",
} if {
	n := name(component)
	is_rsa_pkcs1_v15_name(n)
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "name",
	"value": name(component),
	"ref": "Agreed signature schemes",
} if {
	name(component) in {
		"rsa-pss",
		"kcdsa",
		"schnorr",
		"dsa",
		"ec-kcdsa",
		"ecdsa",
		"ec-dsa",
		"ec-gdsa",
		"ec-schnorr",
		"ml-dsa",
		"xmss",
		"lms",
		"slh-dsa",
	}
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "name",
	"value": name(component),
	"ref": "RSA PKCS#1 v1.5 signature legacy",
} if {
	n := name(component)
	is_rsa_pkcs1_v15_name(n)
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "name",
	"value": name(component),
	"ref": "Agreed KE/KEM schemes",
} if {
	name(component) in {
		"dh",
		"dlies-kem",
		"ec-dh",
		"ecdh",
		"ecies-kem",
		"ml-kem",
		"frodokem",
	}
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "name",
	"value": name(component),
	"ref": "Agreed DRBG",
} if {
	name(component) in {"hmac_drbg", "hash_drbg", "ctr_drbg"}
}

############################
# TLS status
############################

eccg_tls_version_status(component) := {
	"status": "recommended",
	"property": "protocolVersion",
	"value": tls_version(component),
	"ref": "TLSv1.3",
} if {
	is_tls(component)
	tls_version(component) == "tlsv1.3"
}

eccg_tls_version_status(component) := {
	"status": "legacy",
	"property": "protocolVersion",
	"value": tls_version(component),
	"ref": "TLSv1.2",
} if {
	is_tls(component)
	tls_version(component) == "tlsv1.2"
}

eccg_tls_cipher_status(component) := {
	"status": "recommended",
	"property": "cipherSuite",
	"value": tls_cipher_suite(component),
	"ref": "ECCG TLS v1.3 agreed suites",
} if {
	is_tls(component)
	tls_cipher_suite(component) in {
		"tls_aes_256_gcm_sha384",
		"tls_aes_128_gcm_sha256",
		"tls_aes_128_ccm_sha256",
	}
}

eccg_tls_cipher_status(component) := {
	"status": "legacy",
	"property": "cipherSuite",
	"value": tls_cipher_suite(component),
	"ref": "ECCG TLS v1.2 agreed legacy suites",
} if {
	is_tls(component)
	tls_cipher_suite(component) in {
		"tls_ecdhe_ecdsa_with_aes_256_gcm_sha384",
		"tls_ecdhe_ecdsa_with_aes_128_gcm_sha256",
		"tls_ecdhe_ecdsa_with_aes_256_ccm",
		"tls_ecdhe_ecdsa_with_aes_128_ccm",
		"tls_ecdhe_ecdsa_with_aes_256_cbc_sha384",
		"tls_ecdhe_ecdsa_with_aes_128_cbc_sha256",
		"tls_ecdhe_rsa_with_aes_256_cbc_sha384",
		"tls_ecdhe_rsa_with_aes_128_cbc_sha256",
		"tls_ecdhe_rsa_with_aes_256_gcm_sha384",
		"tls_ecdhe_rsa_with_aes_128_gcm_sha256",
		"tls_dhe_rsa_with_aes_256_gcm_sha384",
		"tls_dhe_rsa_with_aes_128_gcm_sha256",
		"tls_dhe_rsa_with_aes_256_ccm",
		"tls_dhe_rsa_with_aes_128_ccm",
		"tls_dhe_rsa_with_aes_256_cbc_sha256",
		"tls_dhe_rsa_with_aes_128_cbc_sha256",
		"tls_rsa_with_aes_256_gcm_sha384",
		"tls_rsa_with_aes_128_gcm_sha256",
		"tls_rsa_with_aes_256_ccm",
		"tls_rsa_with_aes_128_ccm",
		"tls_rsa_with_aes_256_cbc_sha256",
		"tls_rsa_with_aes_128_cbc_sha256",
	}
}

############################
# Findings
############################

eccg_v2.findings contains finding if {
	some component in input.components
	s := eccg_algorithm_status(component)
	finding := mk_finding(
		component,
		"eccg_v2_algorithm_status",
		s.status,
		s.property,
		s.value,
	)
}

eccg_v2.findings contains finding if {
	some component in input.components
	s := eccg_tls_version_status(component)
	finding := mk_finding(
		component,
		"eccg_v2_tls_version_status",
		s.status,
		s.property,
		s.value,
	)
}

eccg_v2.findings contains finding if {
	some component in input.components
	s := eccg_tls_cipher_status(component)
	finding := mk_finding(
		component,
		"eccg_v2_tls_cipher_suite_status",
		s.status,
		s.property,
		s.value,
	)
}
