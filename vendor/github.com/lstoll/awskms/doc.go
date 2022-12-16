// Package awskms implements a crypto.Signer that uses AWS's KMS service
//
// e.g for creating a suitible key:
// `aws kms create-key --customer-master-key-spec RSA_2048 --key-usage SIGN_VERIFY`
// `aws kms create-key --customer-master-key-spec RSA_2048 --key-usage ENCRYPT_DECRYPT`
package awskms
