#ifndef PE_H
#define PE_H


#include <Windows.h>
#include <stdio.h>
#include<mscat.h>
#include <io.h>
#include <bcrypt.h>
#include "md.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)


#ifndef __WINDOWS_PE_H
#define __WINDOWS_PE_H


#define MZ_MAGIC	0x5a4d	/* "MZ" */

#define PE_MAGIC		0x00004550	/* "PE\0\0" */
#define PE_OPT_MAGIC_PE32	0x010b
#define PE_OPT_MAGIC_PE32_ROM	0x0107
#define PE_OPT_MAGIC_PE32PLUS	0x020b

// /* machine type */
//#define	IMAGE_FILE_MACHINE_UNKNOWN	0x0000
//#define	IMAGE_FILE_MACHINE_AM33		0x01d3
//#define	IMAGE_FILE_MACHINE_AMD64	0x8664
//#define	IMAGE_FILE_MACHINE_ARM		0x01c0
//#define	IMAGE_FILE_MACHINE_ARMV7	0x01c4
//#define	IMAGE_FILE_MACHINE_ARM64	0xaa64
//#define	IMAGE_FILE_MACHINE_EBC		0x0ebc
//#define	IMAGE_FILE_MACHINE_I386		0x014c
//#define	IMAGE_FILE_MACHINE_IA64		0x0200
//#define	IMAGE_FILE_MACHINE_M32R		0x9041
//#define	IMAGE_FILE_MACHINE_MIPS16	0x0266
//#define	IMAGE_FILE_MACHINE_MIPSFPU	0x0366
//#define	IMAGE_FILE_MACHINE_MIPSFPU16	0x0466
//#define	IMAGE_FILE_MACHINE_POWERPC	0x01f0
//#define	IMAGE_FILE_MACHINE_POWERPCFP	0x01f1
//#define	IMAGE_FILE_MACHINE_R4000	0x0166
//#define	IMAGE_FILE_MACHINE_SH3		0x01a2
//#define	IMAGE_FILE_MACHINE_SH3DSP	0x01a3
//#define	IMAGE_FILE_MACHINE_SH3E		0x01a4
//#define	IMAGE_FILE_MACHINE_SH4		0x01a6
//#define	IMAGE_FILE_MACHINE_SH5		0x01a8
//#define	IMAGE_FILE_MACHINE_THUMB	0x01c2
//#define	IMAGE_FILE_MACHINE_WCEMIPSV2	0x0169
//
///* flags */
//#define IMAGE_FILE_RELOCS_STRIPPED           0x0001
//#define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002
//#define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004
//#define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008
//#define IMAGE_FILE_AGGRESSIVE_WS_TRIM        0x0010
//#define IMAGE_FILE_LARGE_ADDRESS_AWARE       0x0020
//#define IMAGE_FILE_16BIT_MACHINE             0x0040
//#define IMAGE_FILE_BYTES_REVERSED_LO         0x0080
//#define IMAGE_FILE_32BIT_MACHINE             0x0100
//#define IMAGE_FILE_DEBUG_STRIPPED            0x0200
//#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400
//#define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800
//#define IMAGE_FILE_SYSTEM                    0x1000
//#define IMAGE_FILE_DLL                       0x2000
//#define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000
//#define IMAGE_FILE_BYTES_REVERSED_HI         0x8000
//
//#define IMAGE_FILE_OPT_ROM_MAGIC	0x107
//#define IMAGE_FILE_OPT_PE32_MAGIC	0x10b
//#define IMAGE_FILE_OPT_PE32_PLUS_MAGIC	0x20b
//
//#define IMAGE_SUBSYSTEM_UNKNOWN			 0
//#define IMAGE_SUBSYSTEM_NATIVE			 1
//#define IMAGE_SUBSYSTEM_WINDOWS_GUI		 2
//#define IMAGE_SUBSYSTEM_WINDOWS_CUI		 3
//#define IMAGE_SUBSYSTEM_POSIX_CUI		 7
//#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI		 9
//#define IMAGE_SUBSYSTEM_EFI_APPLICATION		10
//#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER	11
//#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER	12
//#define IMAGE_SUBSYSTEM_EFI_ROM_IMAGE		13
//#define IMAGE_SUBSYSTEM_XBOX			14
//
//#define IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE          0x0040
//#define IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY       0x0080
//#define IMAGE_DLL_CHARACTERISTICS_NX_COMPAT             0x0100
//#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION           0x0200
//#define IMAGE_DLLCHARACTERISTICS_NO_SEH                 0x0400
//#define IMAGE_DLLCHARACTERISTICS_NO_BIND                0x0800
//#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER             0x2000
//#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE  0x8000
//
///* they actually defined 0x00000000 as well, but I think we'll skip that one. */
//#define IMAGE_SCN_RESERVED_0	0x00000001
//#define IMAGE_SCN_RESERVED_1	0x00000002
//#define IMAGE_SCN_RESERVED_2	0x00000004
//#define IMAGE_SCN_TYPE_NO_PAD	0x00000008 /* don't pad - obsolete */
//#define IMAGE_SCN_RESERVED_3	0x00000010
//#define IMAGE_SCN_CNT_CODE	0x00000020 /* .text */
//#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040 /* .data */
//#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080 /* .bss */
//#define IMAGE_SCN_LNK_OTHER	0x00000100 /* reserved */
//#define IMAGE_SCN_LNK_INFO	0x00000200 /* .drectve comments */
//#define IMAGE_SCN_RESERVED_4	0x00000400
//#define IMAGE_SCN_LNK_REMOVE	0x00000800 /* .o only - scn to be rm'd*/
//#define IMAGE_SCN_LNK_COMDAT	0x00001000 /* .o only - COMDAT data */
//#define IMAGE_SCN_RESERVED_5	0x00002000 /* spec omits this */
//#define IMAGE_SCN_RESERVED_6	0x00004000 /* spec omits this */
//#define IMAGE_SCN_GPREL		0x00008000 /* global pointer referenced data */
///* spec lists 0x20000 twice, I suspect they meant 0x10000 for one of them */
//#define IMAGE_SCN_MEM_PURGEABLE	0x00010000 /* reserved for "future" use */
//#define IMAGE_SCN_16BIT		0x00020000 /* reserved for "future" use */
//#define IMAGE_SCN_LOCKED	0x00040000 /* reserved for "future" use */
//#define IMAGE_SCN_PRELOAD	0x00080000 /* reserved for "future" use */
///* and here they just stuck a 1-byte integer in the middle of a bitfield */
//#define IMAGE_SCN_ALIGN_1BYTES	0x00100000 /* it does what it says on the box */
//#define IMAGE_SCN_ALIGN_2BYTES	0x00200000
//#define IMAGE_SCN_ALIGN_4BYTES	0x00300000
//#define IMAGE_SCN_ALIGN_8BYTES	0x00400000
//#define IMAGE_SCN_ALIGN_16BYTES	0x00500000
//#define IMAGE_SCN_ALIGN_32BYTES	0x00600000
//#define IMAGE_SCN_ALIGN_64BYTES	0x00700000
//#define IMAGE_SCN_ALIGN_128BYTES 0x00800000
//#define IMAGE_SCN_ALIGN_256BYTES 0x00900000
//#define IMAGE_SCN_ALIGN_512BYTES 0x00a00000
//#define IMAGE_SCN_ALIGN_1024BYTES 0x00b00000
//#define IMAGE_SCN_ALIGN_2048BYTES 0x00c00000
//#define IMAGE_SCN_ALIGN_4096BYTES 0x00d00000
//#define IMAGE_SCN_ALIGN_8192BYTES 0x00e00000
//#define IMAGE_SCN_LNK_NRELOC_OVFL 0x01000000 /* extended relocations */
//#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000 /* scn can be discarded */
//#define IMAGE_SCN_MEM_NOT_CACHED 0x04000000 /* cannot be cached */
//#define IMAGE_SCN_MEM_NOT_PAGED	0x08000000 /* not pageable */
//#define IMAGE_SCN_MEM_SHARED	0x10000000 /* can be shared */
//#define IMAGE_SCN_MEM_EXECUTE	0x20000000 /* can be executed as code */
//#define IMAGE_SCN_MEM_READ	0x40000000 /* readable */
//#define IMAGE_SCN_MEM_WRITE	0x80000000 /* writeable */
//
//#define IMAGE_DEBUG_TYPE_CODEVIEW	2

#ifndef __ASSEMBLY__

struct Certificate {
	char* Name;
	int NameLen;
	char* SubjectRDN;
	int SubjectRDNLen;
	char* SerialNumber;
	int SerialNumberLen;
	char* Thumbprint;
	int ThumbprintLen;
	char* IssuerName;
	int IssuerNameLen;
	char* IssuerRDN;
	int IssuerRDNLen;
	char* ValidFrom;
	int ValidFromLen;
	char* ValidTo;
	int ValidToLen;


	mbedtls_md_type_t Algorithm;
	char* SubjectPublicKeyInfo;
	int SubjectPublicKeyInfoLen;
	int SubjectPublicKeyExponent;
	char* SignatureValue;
	int SignatureValueLen;
	char* tbsCertHashValue;
	int tbsCertHashValueLen;


	struct Certificate* next;
};

struct mz_hdr {
	UINT16 magic;		/* MZ_MAGIC */
	UINT16 lbsize;	/* size of last used block */
	UINT16 blocks;	/* pages in file, 0x3 */
	UINT16 relocs;	/* relocations */
	UINT16 hdrsize;	/* header size in "paragraphs" */
	UINT16 min_extra_pps;	/* .bss */
	UINT16 max_extra_pps;	/* runtime limit for the arena size */
	UINT16 ss;		/* relative stack segment */
	UINT16 sp;		/* initial %sp register */
	UINT16 checksum;	/* word checksum */
	UINT16 ip;		/* initial %ip register */
	UINT16 cs;		/* initial %cs relative to load segment */
	UINT16 reloc_table_offset;	/* offset of the first relocation */
	UINT16 overlay_num;	/* overlay number.  set to 0. */
	UINT16 reserved0[4];	/* reserved */
	UINT16 oem_id;	/* oem identifier */
	UINT16 oem_info;	/* oem specific */
	UINT16 reserved1[10];	/* reserved */
	UINT32 peaddr;	/* address of pe header */
};

struct mz_reloc {
	UINT16 offset;
	UINT16 segment;
};

struct pe_hdr {
	UINT32 magic;		/* PE magic */
	UINT16 machine;	/* machine type */
	UINT16 sections;	/* number of sections */
	UINT32 timestamp;	/* time_t */
	UINT32 symbol_table;	/* symbol table offset */
	UINT32 symbols;	/* number of symbols */
	UINT16 opt_hdr_size;	/* size of optional header */
	UINT16 flags;		/* flags */
};

/* the fact that pe32 isn't padded where pe32+ is 64-bit means union won't
 * work right.  vomit. */
struct pe32_opt_hdr {
	/* "standard" header */
	UINT16 magic;		/* file type */
	UINT8  ld_major;	/* linker major version */
	UINT8  ld_minor;	/* linker minor version */
	UINT32 text_size;	/* size of text section(s) */
	UINT32 data_size;	/* size of data section(s) */
	UINT32 bss_size;	/* size of bss section(s) */
	UINT32 entry_point;	/* file offset of entry point */
	UINT32 code_base;	/* relative code addr in ram */
	UINT32 data_base;	/* relative data addr in ram */
	/* "windows" header */
	UINT32 image_base;	/* preferred load address */
	UINT32 section_align;	/* alignment in bytes */
	UINT32 file_align;	/* file alignment in bytes */
	UINT16 os_major;	/* major OS version */
	UINT16 os_minor;	/* minor OS version */
	UINT16 image_major;	/* major image version */
	UINT16 image_minor;	/* minor image version */
	UINT16 subsys_major;	/* major subsystem version */
	UINT16 subsys_minor;	/* minor subsystem version */
	UINT32 win32_version;	/* reserved, must be 0 */
	UINT32 image_size;	/* image size */
	UINT32 header_size;	/* header size rounded up to
				   file_align */
	UINT32 csum;		/* checksum */
	UINT16 subsys;	/* subsystem */
	UINT16 dll_flags;	/* more flags! */
	UINT32 stack_size_req;/* amt of stack requested */
	UINT32 stack_size;	/* amt of stack required */
	UINT32 heap_size_req;	/* amt of heap requested */
	UINT32 heap_size;	/* amt of heap required */
	UINT32 loader_flags;	/* reserved, must be 0 */
	UINT32 data_dirs;	/* number of data dir entries */
};

struct pe32plus_opt_hdr {
	UINT16 magic;		/* file type */
	UINT8  ld_major;	/* linker major version */
	UINT8  ld_minor;	/* linker minor version */
	UINT32 text_size;	/* size of text section(s) */
	UINT32 data_size;	/* size of data section(s) */
	UINT32 bss_size;	/* size of bss section(s) */
	UINT32 entry_point;	/* file offset of entry point */
	UINT32 code_base;	/* relative code addr in ram */
	/* "windows" header */
	UINT64 image_base;	/* preferred load address */
	UINT32 section_align;	/* alignment in bytes */
	UINT32 file_align;	/* file alignment in bytes */
	UINT16 os_major;	/* major OS version */
	UINT16 os_minor;	/* minor OS version */
	UINT16 image_major;	/* major image version */
	UINT16 image_minor;	/* minor image version */
	UINT16 subsys_major;	/* major subsystem version */
	UINT16 subsys_minor;	/* minor subsystem version */
	UINT32 win32_version;	/* reserved, must be 0 */
	UINT32 image_size;	/* image size */
	UINT32 header_size;	/* header size rounded up to
				   file_align */
	UINT32 csum;		/* checksum */
	UINT16 subsys;	/* subsystem */
	UINT16 dll_flags;	/* more flags! */
	UINT64 stack_size_req;/* amt of stack requested */
	UINT64 stack_size;	/* amt of stack required */
	UINT64 heap_size_req;	/* amt of heap requested */
	UINT64 heap_size;	/* amt of heap required */
	UINT32 loader_flags;	/* reserved, must be 0 */
	UINT32 data_dirs;	/* number of data dir entries */
};

struct data_dirent {
	UINT32 virtual_address;	/* relative to load address */
	UINT32 size;
};

struct data_directory {
	struct data_dirent exports;		/* .edata */
	struct data_dirent imports;		/* .idata */
	struct data_dirent resources;		/* .rsrc */
	struct data_dirent exceptions;		/* .pdata */
	struct data_dirent certs;		/* certs */
	struct data_dirent base_relocations;	/* .reloc */
	struct data_dirent debug;		/* .debug */
	struct data_dirent arch;		/* reservered */
	struct data_dirent global_ptr;		/* global pointer reg. Size=0 */
	struct data_dirent tls;			/* .tls */
	struct data_dirent load_config;		/* load configuration structure */
	struct data_dirent bound_imports;	/* no idea */
	struct data_dirent import_addrs;	/* import address table */
	struct data_dirent delay_imports;	/* delay-load import table */
	struct data_dirent clr_runtime_hdr;	/* .cor (object only) */
	struct data_dirent reserved;
};

struct section_header {
	char name[8];			/* name or "/12\0" string tbl offset */
	UINT32 virtual_size;		/* size of loaded section in ram */
	UINT32 virtual_address;	/* relative virtual address */
	UINT32 raw_data_size;		/* size of the section */
	UINT32 data_addr;		/* file pointer to first page of sec */
	UINT32 relocs;		/* file pointer to relocation entries */
	UINT32 line_numbers;		/* line numbers! */
	UINT16 num_relocs;		/* number of relocations */
	UINT16 num_lin_numbers;	/* srsly. */
	UINT32 flags;
};

//struct IMAGE_RESOURCE_DIRECTORY {
//	UINT32   Characteristics;
//	UINT32   TimeDateStamp;
//	UINT16    MajorVersion;
//	UINT16    MinorVersion;
//	UINT16    NumberOfNamedEntries;
//	UINT16    NumberOfIdEntries;
//	//  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
//};
//
//struct IMAGE_RESOURCE_DIRECTORY_ENTRY {
//	union {
//		struct {
//			DWORD NameOffset : 31;
//			DWORD NameIsString : 1;
//		} DUMMYSTRUCTNAME;
//		DWORD   Name;
//		WORD    Id;
//	} DUMMYUNIONNAME;
//	union {
//		DWORD   OffsetToData;
//		struct {
//			DWORD   OffsetToDirectory : 31;
//			DWORD   DataIsDirectory : 1;
//		} DUMMYSTRUCTNAME2;
//	} DUMMYUNIONNAME2;
//};
//
//struct IMAGE_RESOURCE_DATA_ENTRY {
//	UINT32   DataOffset;
//	UINT32   Size;
//	UINT32    CodePage;
//	UINT32    Reserved;
//};

typedef struct _VS_FIXEDFILEINFO {
	DWORD dwSignature;
	DWORD dwStrucVersion;
	DWORD dwFileVersionMS;
	DWORD dwFileVersionLS;
	DWORD dwProductVersionMS;
	DWORD dwProductVersionLS;
	DWORD dwFileFlagsMask;
	DWORD dwFileFlags;
	DWORD dwFileOS;
	DWORD dwFileType;
	DWORD dwFileSubtype;
	DWORD dwFileDateMS;
	DWORD dwFileDateLS;
} VS_FIXEDFILEINFO_1;

typedef struct {
	WORD  wLength;
	WORD  wValueLength;
	WORD  wType;
	WCHAR szKey;
	WORD  Padding;
	WORD  Value;
} String;

typedef struct {
	WORD   wLength;
	WORD   wValueLength;
	WORD   wType;
	WCHAR  szKey;
	WORD   Padding;
	String Children;
} StringTable;

typedef struct {
	WORD        wLength;
	WORD        wValueLength;
	WORD        wType;
	WCHAR       szKey;
	WORD        Padding;
	StringTable Children;
} StringFileInfo;

typedef struct {
	WORD  wLength;
	WORD  wValueLength;
	WORD  wType;
	WCHAR szKey;
	WORD  Padding;
	DWORD Value;
} Var;

typedef struct {
	WORD  wLength;
	WORD  wValueLength;
	WORD  wType;
	WCHAR szKey;
	WORD  Padding;
	Var   Children;
} VarFileInfo;

struct VS_VERSIONINFO {
	WORD             wLength;
	WORD             wValueLength;
	WORD             wType;
	WCHAR            szKey;
	WORD             Padding1;
	VS_FIXEDFILEINFO Value;
	WORD             Padding2;
	WORD             Children;
};


/*
enum x64_coff_reloc_type {
	x64_coff_reloc_type_IMAGE_REL_AMD64_ABSOLUTE,
	x64_coff_reloc_type_IMAGE_REL_AMD64_ADDR64,
	x64_coff_reloc_type_IMAGE_REL_AMD64_ADDR32,
	x64_coff_reloc_type_IMAGE_REL_AMD64_ADDR32N,
	x64_coff_reloc_type_IMAGE_REL_AMD64_REL32,
	x64_coff_reloc_type_IMAGE_REL_AMD64_REL32_1,
	x64_coff_reloc_type_IMAGE_REL_AMD64_REL32_2,
	x64_coff_reloc_type_IMAGE_REL_AMD64_REL32_3,
	x64_coff_reloc_type_IMAGE_REL_AMD64_REL32_4,
	x64_coff_reloc_type_IMAGE_REL_AMD64_REL32_5,
	x64_coff_reloc_type_IMAGE_REL_AMD64_SECTION,
	x64_coff_reloc_type_IMAGE_REL_AMD64_SECREL,
	x64_coff_reloc_type_IMAGE_REL_AMD64_SECREL7,
	x64_coff_reloc_type_IMAGE_REL_AMD64_TOKEN,
	x64_coff_reloc_type_IMAGE_REL_AMD64_SREL32,
	x64_coff_reloc_type_IMAGE_REL_AMD64_PAIR,
	x64_coff_reloc_type_IMAGE_REL_AMD64_SSPAN32,
};

enum arm_coff_reloc_type {
	arm_coff_reloc_type_IMAGE_REL_ARM_ABSOLUTE,
	arm_coff_reloc_type_IMAGE_REL_ARM_ADDR32,
	arm_coff_reloc_type_IMAGE_REL_ARM_ADDR32N,
	arm_coff_reloc_type_IMAGE_REL_ARM_BRANCH2,
	arm_coff_reloc_type_IMAGE_REL_ARM_BRANCH1,
	arm_coff_reloc_type_IMAGE_REL_ARM_SECTION,
	arm_coff_reloc_type_IMAGE_REL_ARM_SECREL,
};

enum sh_coff_reloc_type {
	IMAGE_REL_SH3_ABSOLUTE,
	IMAGE_REL_SH3_DIRECT16,
	IMAGE_REL_SH3_DIRECT32,
	IMAGE_REL_SH3_DIRECT8,
	IMAGE_REL_SH3_DIRECT8_WORD,
	IMAGE_REL_SH3_DIRECT8_LONG,
	IMAGE_REL_SH3_DIRECT4,
	IMAGE_REL_SH3_DIRECT4_WORD,
	IMAGE_REL_SH3_DIRECT4_LONG,
	IMAGE_REL_SH3_PCREL8_WORD,
	IMAGE_REL_SH3_PCREL8_LONG,
	IMAGE_REL_SH3_PCREL12_WORD,
	IMAGE_REL_SH3_STARTOF_SECTION,
	IMAGE_REL_SH3_SIZEOF_SECTION,
	IMAGE_REL_SH3_SECTION,
	IMAGE_REL_SH3_SECREL,
	IMAGE_REL_SH3_DIRECT32_NB,
	IMAGE_REL_SH3_GPREL4_LONG,
	IMAGE_REL_SH3_TOKEN,
	IMAGE_REL_SHM_PCRELPT,
	IMAGE_REL_SHM_REFLO,
	IMAGE_REL_SHM_REFHALF,
	IMAGE_REL_SHM_RELLO,
	IMAGE_REL_SHM_RELHALF,
	IMAGE_REL_SHM_PAIR,
	IMAGE_REL_SHM_NOMODE,
};

enum ppc_coff_reloc_type {
	IMAGE_REL_PPC_ABSOLUTE,
	IMAGE_REL_PPC_ADDR64,
	IMAGE_REL_PPC_ADDR32,
	IMAGE_REL_PPC_ADDR24,
	IMAGE_REL_PPC_ADDR16,
	IMAGE_REL_PPC_ADDR14,
	IMAGE_REL_PPC_REL24,
	IMAGE_REL_PPC_REL14,
	IMAGE_REL_PPC_ADDR32N,
	IMAGE_REL_PPC_SECREL,
	IMAGE_REL_PPC_SECTION,
	IMAGE_REL_PPC_SECREL16,
	IMAGE_REL_PPC_REFHI,
	IMAGE_REL_PPC_REFLO,
	IMAGE_REL_PPC_PAIR,
	IMAGE_REL_PPC_SECRELLO,
	IMAGE_REL_PPC_GPREL,
	IMAGE_REL_PPC_TOKEN,
};

enum x86_coff_reloc_type {
	IMAGE_REL_I386_ABSOLUTE,
	IMAGE_REL_I386_DIR16,
	IMAGE_REL_I386_REL16,
	IMAGE_REL_I386_DIR32,
	IMAGE_REL_I386_DIR32NB,
	IMAGE_REL_I386_SEG12,
	IMAGE_REL_I386_SECTION,
	IMAGE_REL_I386_SECREL,
	IMAGE_REL_I386_TOKEN,
	IMAGE_REL_I386_SECREL7,
	IMAGE_REL_I386_REL32,
};

enum ia64_coff_reloc_type {
	IMAGE_REL_IA64_ABSOLUTE,
	IMAGE_REL_IA64_IMM14,
	IMAGE_REL_IA64_IMM22,
	IMAGE_REL_IA64_IMM64,
	IMAGE_REL_IA64_DIR32,
	IMAGE_REL_IA64_DIR64,
	IMAGE_REL_IA64_PCREL21B,
	IMAGE_REL_IA64_PCREL21M,
	IMAGE_REL_IA64_PCREL21F,
	IMAGE_REL_IA64_GPREL22,
	IMAGE_REL_IA64_LTOFF22,
	IMAGE_REL_IA64_SECTION,
	IMAGE_REL_IA64_SECREL22,
	IMAGE_REL_IA64_SECREL64I,
	IMAGE_REL_IA64_SECREL32,
	IMAGE_REL_IA64_DIR32NB,
	IMAGE_REL_IA64_SREL14,
	IMAGE_REL_IA64_SREL22,
	IMAGE_REL_IA64_SREL32,
	IMAGE_REL_IA64_UREL32,
	IMAGE_REL_IA64_PCREL60X,
	IMAGE_REL_IA64_PCREL60B,
	IMAGE_REL_IA64_PCREL60F,
	IMAGE_REL_IA64_PCREL60I,
	IMAGE_REL_IA64_PCREL60M,
	IMAGE_REL_IA64_IMMGPREL6,
	IMAGE_REL_IA64_TOKEN,
	IMAGE_REL_IA64_GPREL32,
	IMAGE_REL_IA64_ADDEND,
};



struct coff_reloc {
	UINT32 virtual_address;
	UINT32 symbol_table_index;
	union {
		enum x64_coff_reloc_type  x64_type;
		enum arm_coff_reloc_type  arm_type;
		enum sh_coff_reloc_type   sh_type;
		enum ppc_coff_reloc_type  ppc_type;
		enum x86_coff_reloc_type  x86_type;
		enum ia64_coff_reloc_type ia64_type;
		UINT16 data;
	};
};


*/

/*
 * Definitions for the contents of the certs data block
 */
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA	0x0002
#define WIN_CERT_TYPE_EFI_OKCS115	0x0EF0
#define WIN_CERT_TYPE_EFI_GUID		0x0EF1

#define WIN_CERT_REVISION_1_0	0x0100
#define WIN_CERT_REVISION_2_0	0x0200

struct win_certificate {
	UINT32 length;
	UINT16 revision;
	UINT16 cert_type;
};




struct pefile_context {
	unsigned	header_size;
	unsigned	image_checksum_offset;
	unsigned	cert_dirent_offset;
	unsigned	n_data_dirents;
	unsigned	n_sections;
	unsigned	certs_size;
	unsigned	sig_offset;
	unsigned	sig_len;
	const struct section_header* secs;
	unsigned	resource_viirtualaddr;

	/* PKCS#7 MS Individual Code Signing content */
	char* pkcs;
	const void* digest;		/* Digest */
	unsigned	digest_len;		/* Digest length */
	const char* digest_algo;		/* Digest algorithm */
};


#define ELIBBAD 100
#define  ENOTSUPP	101
#define  EKEYREJECTED	102

#endif /* !__ASSEMBLY__ */

#endif /* __WINDOWS_PE_H */



#ifndef _WINDOWS_ASN1_H
#define _WINDOWS_ASN1_H

/* Class */
enum asn1_class {
	ASN1_UNIV = 0,	/* Universal */
	ASN1_APPL = 1,	/* Application */
	ASN1_CONT = 2,	/* Context */
	ASN1_PRIV = 3	/* Private */
};
#define ASN1_CLASS_BITS	0xc0


enum asn1_method {
	ASN1_PRIM = 0,	/* Primitive */
	ASN1_CONS = 1	/* Constructed */
};
#define ASN1_CONS_BIT	0x20

/* Tag */
enum asn1_tag {
	ASN1_EOC = 0,	/* End Of Contents or N/A */
	ASN1_BOOL = 1,	/* Boolean */
	ASN1_INT = 2,	/* Integer */
	ASN1_BTS = 3,	/* Bit String */
	ASN1_OTS = 4,	/* Octet String */
	ASN1_NULL = 5,	/* Null */
	ASN1_OID = 6,	/* Object Identifier  */
	ASN1_ODE = 7,	/* Object Description */
	ASN1_EXT = 8,	/* External */
	ASN1_REAL = 9,	/* Real float */
	ASN1_ENUM = 10,	/* Enumerated */
	ASN1_EPDV = 11,	/* Embedded PDV */
	ASN1_UTF8STR = 12,	/* UTF8 String */
	ASN1_RELOID = 13,	/* Relative OID */
	/* 14 - Reserved */
	/* 15 - Reserved */
	ASN1_SEQ = 16,	/* Sequence and Sequence of */
	ASN1_SET = 17,	/* Set and Set of */
	ASN1_NUMSTR = 18,	/* Numerical String */
	ASN1_PRNSTR = 19,	/* Printable String */
	ASN1_TEXSTR = 20,	/* T61 String / Teletext String */
	ASN1_VIDSTR = 21,	/* Videotex String */
	ASN1_IA5STR = 22,	/* IA5 String */
	ASN1_UNITIM = 23,	/* Universal Time */
	ASN1_GENTIM = 24,	/* General Time */
	ASN1_GRASTR = 25,	/* Graphic String */
	ASN1_VISSTR = 26,	/* Visible String */
	ASN1_GENSTR = 27,	/* General String */
	ASN1_UNISTR = 28,	/* Universal String */
	ASN1_CHRSTR = 29,	/* Character String */
	ASN1_BMPSTR = 30,	/* BMP String */
	ASN1_LONG_TAG = 31	/* Long form tag */
};

#define ASN1_INDEFINITE_LENGTH 0x80

void printAsHex(char* cp, size_t len);




struct PESignInfo {
	int Signed;
	int Verified;
	int IsZohoSigned;

	int SignType;
	long SignTimeStamp;
	char* Publisher;
	char* Thumbprint;
	char* SignAlgo;
};

#endif /* _WINDOWS_ASN1_H */


#endif // !PE_H
