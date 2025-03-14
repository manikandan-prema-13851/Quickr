#ifndef HASH_H
#define HASH_H


#include "pe.h"

__declspec(noinline) int calculateHash(mbedtls_md_type_t algoType, char* buffer, size_t len, OUT char** digestOut, OUT int* digestOutLen);

#endif // !HASH_H
