
#ifndef PE_HASH_H
#define PE_HASH_H

#include "pe.h"

/*
*	To calculate the PE Hash follow the Header "Calculating the PE Image Hash" from 
*	http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx
* 
* (For immediate ref)
* To calculate the hash value
1.	Load the image header into memory.
2.	Initialize a hash algorithm context.
3.	Hash the image header from its base to immediately before the start of the checksum address, as specified in Optional Header Windows-Specific Fields.
4.	Skip over the checksum, which is a 4-byte field.
5.	Hash everything from the end of the checksum field to immediately before the start of the Certificate Table entry, as specified in Optional Header Data Directories.
6.	Get the Attribute Certificate Table address and size from the Certificate Table entry. For details, see section 5.7 of the PE/COFF specification.
7.	Exclude the Certificate Table entry from the calculation and hash everything from the end of the Certificate Table entry to the end of image header, including Section Table (headers).The Certificate Table entry is 8 bytes long, as specified in Optional Header Data Directories. 
8.	Create a counter called SUM_OF_BYTES_HASHED, which is not part of the signature. Set this counter to the SizeOfHeaders field, as specified in Optional Header Windows-Specific Field.
9.	Build a temporary table of pointers to all of the section headers in the image. The NumberOfSections field of COFF File Header indicates how big the table should be. Do not include any section headers in the table whose SizeOfRawData field is zero. 
10.	Using the PointerToRawData field (offset 20) in the referenced SectionHeader structure as a key, arrange the table's elements in ascending order. In other words, sort the section headers in ascending order according to the disk-file offset of the sections.
11.	Walk through the sorted table, load the corresponding section into memory, and hash the entire section. Use the SizeOfRawData field in the SectionHeader structure to determine the amount of data to hash.
12.	Add the section�s SizeOfRawData value to SUM_OF_BYTES_HASHED.
13.	Repeat steps 11 and 12 for all of the sections in the sorted table.
14.	Create a value called FILE_SIZE, which is not part of the signature. Set this value to the image�s file size, acquired from the underlying file system. If FILE_SIZE is greater than SUM_OF_BYTES_HASHED, the file contains extra data that must be added to the hash. This data begins at the SUM_OF_BYTES_HASHED file offset, and its length is:
(File Size) � ((Size of AttributeCertificateTable) + SUM_OF_BYTES_HASHED)


Note: The size of Attribute Certificate Table is specified in the second ULONG value in the Certificate Table entry (32 bit: offset 132, 64 bit: offset 148) in Optional Header Data Directories.
15.	Finalize the hash algorithm context.

*/
int pefile_digest_pe(FILE* fp, unsigned int pelen,
	struct pefile_context* ctx, mbedtls_md_type_t algoType, OUT char** digestOut, OUT int* digestOutLen, struct PEImgDetails* data);


#endif // !PE_HASH_H
