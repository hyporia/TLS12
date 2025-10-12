package shared

type SupportedGroup uint16

const (
	SupportedGroupsSecp256r1 SupportedGroup = 0x0017
)

type SignatureAlgorithm uint16

const (
	SignatureAlgorithmRsaPkcs1Sha256 SignatureAlgorithm = 0x0401
	SignatureAlgorithmRsaPkcs1Sha384 SignatureAlgorithm = 0x0501
	SignatureAlgorithmRsaPkcs1Sha512 SignatureAlgorithm = 0x0601

	// ECDSA algorithms
	SignatureAlgorithmEcdsaSecp256r1Sha256 SignatureAlgorithm = 0x0403
	SignatureAlgorithmEcdsaSecp384r1Sha384 SignatureAlgorithm = 0x0503
	SignatureAlgorithmEcdsaSecp521r1Sha512 SignatureAlgorithm = 0x0603

	// RSASSA-PSS algorithms with public key OID rsaEncryption
	SignatureAlgorithmRsaPssRsaeSha256 SignatureAlgorithm = 0x0804
	SignatureAlgorithmRsaPssRsaeSha384 SignatureAlgorithm = 0x0805
	SignatureAlgorithmRsaPssRsaeSha512 SignatureAlgorithm = 0x0806

	// EdDSA algorithms
	SignatureAlgorithmEd25519 SignatureAlgorithm = 0x0807
	SignatureAlgorithmEd448   SignatureAlgorithm = 0x0808

	// RSASSA-PSS algorithms with public key OID RSASSA-PSS
	SignatureAlgorithmRsaPssPssSha256 SignatureAlgorithm = 0x0809
	SignatureAlgorithmRsaPssPssSha384 SignatureAlgorithm = 0x080a
	SignatureAlgorithmRsaPssPssSha512 SignatureAlgorithm = 0x080b

	// Legacy algorithms
	SignatureAlgorithmRsaPkcs1Sha1 SignatureAlgorithm = 0x0201
	SignatureAlgorithmEcdsaSha1    SignatureAlgorithm = 0x0203
)
