#ifndef SIGNATURE_H
#define SIGNATURE_H

#include "pe.h"
#include "Intsafe.h"


NTSTATUS VerifySignature(
    _In_reads_bytes_(MessageDigestLength) PBYTE MessageDigest,        // Pointer to the message digest
    _In_ DWORD MessageDigestLength,                                       // Length of the message digest
    _In_reads_bytes_(SignatureBlobLength) PBYTE SignatureBlob,        // Pointer to the signature blob
    _In_ DWORD SignatureBlobLength,                                       // Length of the signature blob
    _In_ char* PublicKeyModulus,                                          // Pointer to the RSAPUBKEY blob
    _In_ int lenPublicKeyModulus,                                         // Length of the PublicKeyModulus
    _In_ int PublicKeyExponent,                                           // Public key exponent
    _In_ mbedtls_md_type_t algo                                           // Hash algorithm type (e.g., SHA-256)
);

#endif // !SIGNATURE_H
