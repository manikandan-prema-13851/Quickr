#ifndef FILESIGNING_H
#define FILESIGNING_H
#include<Windows.h>
#include<wincrypt.h>
#pragma once

#define MY_ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#ifndef szOID_RFC3161_counterSign
#define szOID_RFC3161_counterSign "1.3.6.1.4.1.311.3.3.1"
#endif
#ifndef szOID_NESTED_SIGNATURE
#define szOID_NESTED_SIGNATURE    "1.3.6.1.4.1.311.2.4.1"
#endif

#define XCH_WORD_LITEND(num) \
    (WORD)(((((WORD)num) & 0xFF00) >> 8) | ((((WORD)num) & 0x00FF) << 8))

#define _8BYTE_ALIGN(offset, base) \
    (((offset+base+7) & 0xFFFFFFF8L)-(base & 0xFFFFFFF8L))



typedef struct _CERT_NODE_INFO {
	char* SubjectName;
	char* IssuerName;
	char* Version;
	char* Serial;
	char* Thumbprint;
	char* NotBefore;
	char* NotAfter;
	char* SignAlgorithm;
	WCHAR* CRLpoint;
} CERT_NODE_INFO, * PCERT_NODE_INFO;

typedef struct _SIGN_COUNTER_SIGN {
	char* SignerName;
	char* MailAddress;
	char* TimeStamp;
} SIGN_COUNTER_SIGN, * PSIGN_COUNTER_SIGN;

typedef struct _SIGN_NODE_INFO {
	char* DigestAlgorithm;
	char* Version;
	SIGN_COUNTER_SIGN CounterSign;
	GenericLL* CertChain; //CERT_NODE_INFO
} SIGN_NODE_INFO, * PSIGN_NODE_INFO;

typedef struct _SIGNDATA_HANDLE {
	DWORD dwObjSize;
	PCMSG_SIGNER_INFO pSignerInfo;
	HCERTSTORE hCertStoreHandle;
} SIGNDATA_HANDLE, * PSIGNDATA_HANDLE;
#endif