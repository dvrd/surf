package loopback

import "core:crypto/ecdsa"
import "core:crypto/hash"
import "core:crypto/x509"
import "core:encoding/pem"
import "core:os"
import "core:time"

FILE_PERM :: os.Permissions{.Read_User, .Write_User}

// Self-signed P-256 root, written as PEM and installed as the handshake
// identity. The core server engine can sign this key; the Ed25519 fixture
// cannot. Callers pass the names the client will check.
mint_p256 :: proc(path, common_name: string, dns: []string, ips: [][]byte) -> bool {
	if !ecdsa.private_key_generate(&peer_p256, .SECP256R1) {
		return false
	}
	if !install_p256(path, common_name, dns, ips) {
		ecdsa.private_key_clear(&peer_p256)
		peer_cert_n = 0
		peer_signer = .Ed25519
		return false
	}
	peer_signer = .P256
	return true
}

install_p256 :: proc(path, common_name: string, dns: []string, ips: [][]byte) -> bool {
	point: [65]u8
	ecdsa.private_key_public_bytes(&peer_p256, point[:])
	name := [1]x509.DN_Attribute{{type = .Common_Name, value = common_name}}
	basic, basic_error := x509.marshal_ext_basic_constraints(true, -1, true)
	if basic_error != nil {
		return false
	}
	defer delete(basic)
	usage, usage_error := x509.marshal_ext_key_usage({.Digital_Signature, .Key_Cert_Sign}, true)
	if usage_error != nil {
		return false
	}
	defer delete(usage)
	eku, eku_error := x509.marshal_ext_ext_key_usage({.Server_Auth}, false)
	if eku_error != nil {
		return false
	}
	defer delete(eku)
	san, san_error := x509.marshal_ext_san(dns, ips, false)
	if san_error != nil {
		return false
	}
	defer delete(san)
	extensions := [4][]byte{basic, usage, eku, san}
	now := time.now()
	serial := [1]u8{1}
	tbs, tbs_error := x509.marshal_tbs_certificate(
		x509.TBS_Certificate {
			serial = serial[:],
			signature_algorithm = .ECDSA_SHA256,
			issuer = name[:],
			not_before = time.time_add(now, -time.Hour),
			not_after = time.time_add(now, time.Hour),
			subject = name[:],
			public_key = {algorithm = .ECDSA_P256, ec_point = point[:]},
			extensions = extensions[:],
		},
	)
	if tbs_error != nil {
		return false
	}
	defer delete(tbs)
	signature, signed := ecdsa.sign_asn1(&peer_p256, .SHA256, tbs, context.allocator)
	if !signed {
		return false
	}
	defer delete(signature)
	der, der_error := x509.marshal_certificate(tbs, .ECDSA_SHA256, signature)
	if der_error != nil || len(der) > len(peer_cert) {
		delete(der)
		return false
	}
	defer delete(der)
	encoded, encode_error := pem.encode("CERTIFICATE", der)
	if encode_error != nil {
		return false
	}
	defer delete(encoded)
	if os.write_entire_file(path, encoded, FILE_PERM) != nil {
		return false
	}
	peer_cert_n = copy(peer_cert[:], der)
	return peer_cert_n == len(der)
}
