#include "CoffHeaderArr.h"
#include<stdio.h>


#define IMAGE_FILE_MACHINE_LOONGARCH32 0x6232
#define IMAGE_FILE_MACHINE_LOONGARCH64 0x6264
#define IMAGE_FILE_MACHINE_RISCV128 0x5128
#define IMAGE_FILE_MACHINE_RISCV32 0x5032
#define IMAGE_FILE_MACHINE_RISCV64 0x5064


__declspec(noinline) void machineHashData(struct FeatNode** head, WORD switchcasevalue) {
	switch (switchcasevalue) {
	case IMAGE_FILE_MACHINE_UNKNOWN: {
		////printf("UNKNOWN\n");
		featNodeAppend(head, "UNKNOWN", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_AM33: {
		//printf("AM33\n");
		featNodeAppend(head, "AM33", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_AMD64: {
		//printf("AMD64\n");
		featNodeAppend(head, "AMD64", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_ARM: {
		//printf("ARM\n");
		featNodeAppend(head, "ARM", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_ARM64: {
		//printf("ARM64\n");
		featNodeAppend(head, "ARM64", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_ARMNT: {
		//printf("ARMNT\n");
		featNodeAppend(head, "ARMNT", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_EBC: {
		//printf("EBC\n");
		featNodeAppend(head, "EBC", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_I386: {
		//printf("I386\n");
		featNodeAppend(head, "I386", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_IA64: {
		//printf("IA64\n");
		featNodeAppend(head, "IA64", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_LOONGARCH32: {
		//printf("LOONGARCH32\n");
		featNodeAppend(head, "LOONGARCH32", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_LOONGARCH64: {
		//printf("LOONGARCH64\n");
		featNodeAppend(head, "LOONGARCH64", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_M32R: {
		//printf("M32R\n");
		featNodeAppend(head, "M32R", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_MIPS16: {
		//printf("MIPS16\n");
		featNodeAppend(head, "MIPS16", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_MIPSFPU: {
		//printf("MIPSFPU\n");
		featNodeAppend(head, "MIPSFPU", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_MIPSFPU16: {
		//printf("MIPSFPU16\n");
		featNodeAppend(head, "MIPSFPU16", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_POWERPC: {
		//printf("POWERPC\n");
		featNodeAppend(head, "POWERPC", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_POWERPCFP: {
		//printf("POWERPCFP\n");
		featNodeAppend(head, "POWERPCFP", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_R4000: {
		//printf("R4000\n");
		featNodeAppend(head, "R4000", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_RISCV32: {
		//printf("RISCV32\n");
		featNodeAppend(head, "RISCV32", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_RISCV64: {
		//printf("RISCV64\n");
		featNodeAppend(head, "RISCV64", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_RISCV128: {
		//printf("RISCV128\n");
		featNodeAppend(head, "RISCV128", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_SH3: {
		//printf("SH3\n");
		featNodeAppend(head, "SH3", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_SH3DSP: {
		//printf("SH3DSP\n");
		featNodeAppend(head, "SH3DSP", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_SH4: {
		//printf("SH4\n");
		featNodeAppend(head, "SH4", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_SH5: {
		//printf("SH5\n");
		featNodeAppend(head, "SH5", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_THUMB: {
		//printf("THUMP\n");
		featNodeAppend(head, "THUMP", 1.0);
		break;
	}
	case IMAGE_FILE_MACHINE_WCEMIPSV2: {
		//printf("WCEMIPSV2\n");
		featNodeAppend(head, "WCEMIPSV2", 1.0);
		break;
	}
	default: {
		break;
	}
	}
}


__declspec(noinline) void charHashData(struct FeatNode** head, WORD switchcasevalue) {
	for (unsigned short int i = 0; i < 16; i++) {
		unsigned  short int subswitchcasevalue = (switchcasevalue) & (0x1 << i);
		switch (subswitchcasevalue) {

		case IMAGE_FILE_RELOCS_STRIPPED: {
			featNodeAppend(head, "RELOCS_STRIPPED", 1.0);
			//printf("RELOCS_STRIPPED\n");
			break;
		}
		case IMAGE_FILE_EXECUTABLE_IMAGE: {
			featNodeAppend(head, "EXECUTABLE_IMAGE", 1.0);
			//printf("EXECUTABLE_IMAGE\n");
			break;
		}
		case IMAGE_FILE_LINE_NUMS_STRIPPED: {
			featNodeAppend(head, "LINE_NUMS_STRIPPED", 1.0);
			//printf("LINE_NUMS_STRIPPED\n");
			break;
		}
		case IMAGE_FILE_LOCAL_SYMS_STRIPPED: {
			featNodeAppend(head, "LOCAL_SYMS_STRIPPED", 1.0);
			//printf("LOCAL_SYMS_STRIPPED\n");
			break;
		}
		case IMAGE_FILE_AGGRESIVE_WS_TRIM: {
			featNodeAppend(head, "AGGRESSIVE_WS_TRIM", 1.0);
			//printf("AGGRESSIVE_WS_TRIM\n");
			break;
		}
		case IMAGE_FILE_LARGE_ADDRESS_AWARE: {
			featNodeAppend(head, "LARGE_ADDRESS_AWARE", 1.0);
			//printf("LARGE_ADDRESS_AWARE\n");
			break;
		}
		case IMAGE_FILE_BYTES_REVERSED_LO: {
			featNodeAppend(head, "BYTES_REVERSED_LO", 1.0);
			//printf("BYTES_REVERSED_LO\n");
			break;
		}
		case IMAGE_FILE_32BIT_MACHINE: {
			featNodeAppend(head, "CHARA_32BIT_MACHINE", 1.0);
			//printf("CHARA_32BIT_MACHINE\n");
			break;
		}
		case IMAGE_FILE_DEBUG_STRIPPED: {
			featNodeAppend(head, "DEBUG_STRIPPED", 1.0);
			//printf("DEBUG_STRIPPED\n");
			break;
		}
		case IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: {
			featNodeAppend(head, "REMOVABLE_RUN_FROM_SWAP", 1.0);
			//printf("REMOVABLE_RUN_FROM_SWAP\n");
			break;
		}
		case IMAGE_FILE_NET_RUN_FROM_SWAP: {
			featNodeAppend(head, "NET_RUN_FROM_SWAP", 1.0);
			//printf("NET_RUN_FROM_SWAP\n");
			break;
		}
		case IMAGE_FILE_SYSTEM: {
			featNodeAppend(head, "SYSTEM", 1.0);
			//printf("SYSTEM\n");
			break;
		}
		case IMAGE_FILE_DLL: {
			featNodeAppend(head, "DLL", 1.0);
			//printf("DLL\n");
			break;
		}
		case IMAGE_FILE_UP_SYSTEM_ONLY: {
			featNodeAppend(head, "UP_SYSTEM_ONLY", 1.0);
			//printf("UP_SYSTEM_ONLY\n");
			break;
		}
		case IMAGE_FILE_BYTES_REVERSED_HI: {
			featNodeAppend(head, "BYTES_REVERSED_HI", 1.0);
			//printf("BYTES_REVERSED_HI\n");
			break;
		}
		default: {
			break;
		}
		}
	}
}


__declspec(noinline) void sectionCharData(struct FeatNode** head, DWORD switchcasevalue, int* MEM_READ_FLAG, int* MEM_EXECUTE_FLAG, int* sectionW, int firstSection) {
	//printf("char ==>  %02X\n", switchcasevalue);

	for (unsigned short int i = 0; i < 32; i++) {
		DWORD subswitchcasevalue = (switchcasevalue) & (0x1 << i);
		//printf("\n\nchar ==>  %02X\n", (0x1 << i));

		switch (subswitchcasevalue) {

		case IMAGE_SCN_TYPE_NO_PAD: {
			//sectionscharclist.push_back("TYPE_NO_PAD");
			//printf("IMAGE_SCN_TYPE_NO_PAD\n");
			if (!firstSection)
				featNodeAppend(head, "TYPE_NO_PAD", 1.0);
			break;
		}
		case IMAGE_SCN_CNT_CODE: {
			//sectionscharclist.push_back("CNT_CODE");
			if (!firstSection)
				featNodeAppend(head, "CNT_CODE", 1.0);
			//printf("IMAGE_SCN_CNT_CODE\n");
			break;
		}
		case IMAGE_SCN_CNT_INITIALIZED_DATA: {
			//sectionscharclist.push_back("CNT_INITIALIZED_DATA");
			if (!firstSection)
				featNodeAppend(head, "CNT_INITIALIZED_DATA", 1.0);

			//printf("IMAGE_SCN_CNT_INITIALIZED_DATA\n");
			break;
		}
		case IMAGE_SCN_CNT_UNINITIALIZED_DATA: {
			//sectionscharclist.push_back("CNT_UNINITIALIZED_DATA");
			if (!firstSection)
				featNodeAppend(head, "CNT_UNINITIALIZED_DATA", 1.0);
			//printf("IMAGE_SCN_CNT_UNINITIALIZED_DATA\n");
			break;
		}
		case IMAGE_SCN_LNK_OTHER: {
			//sectionscharclist.push_back("LNK_OTHER");
			if (!firstSection)
				featNodeAppend(head, "LNK_OTHER", 1.0);
			//printf("IMAGE_SCN_LNK_OTHER\n");
			break;
		}
		case IMAGE_SCN_LNK_INFO: {
			//sectionscharclist.push_back("LNK_INFO");
			if (!firstSection)
				featNodeAppend(head, "LNK_INFO", 1.0);
			//printf("IMAGE_SCN_LNK_INFO\n");
			break;
		}
		case IMAGE_SCN_LNK_REMOVE: {
			//sectionscharclist.push_back("LNK_REMOVE");
			if (!firstSection)
				featNodeAppend(head, "LNK_REMOVE", 1.0);
			//printf("IMAGE_SCN_LNK_REMOVE\n");
			break;
		}
		case IMAGE_SCN_LNK_COMDAT: {
			//sectionscharclist.push_back("LNK_COMDAT");
			if (!firstSection)
				featNodeAppend(head, "LNK_COMDAT", 1.0);
			//printf("IMAGE_SCN_LNK_COMDAT\n");
			break;
		}
		case IMAGE_SCN_GPREL: {
			//sectionscharclist.push_back("GPREL");
			if (!firstSection)
				featNodeAppend(head, "GPREL", 1.0);
			//printf("IMAGE_SCN_GPREL\n");
			break;
		}
		case IMAGE_SCN_MEM_PURGEABLE: {
			//sectionscharclist.push_back("MEM_PURGEABLE");
			if (!firstSection)
				featNodeAppend(head, "MEM_PURGEABLE", 1.0);
			//printf("IMAGE_SCN_MEM_PURGEABLE\n");
			//sectionscharclist.push_back("MEM_16BIT");
			if (!firstSection)
				featNodeAppend(head, "MEM_16BIT", 1.0);
			//printf("IMAGE_SCN_MEM_16BIT\n");
			break;
		}
		case IMAGE_SCN_MEM_LOCKED: {
			//sectionscharclist.push_back("MEM_LOCKED");
			if (!firstSection)
				featNodeAppend(head, "MEM_LOCKED", 1.0);
			//printf("IMAGE_SCN_MEM_LOCKED\n");
			break;
		}
		case IMAGE_SCN_MEM_PRELOAD: {
			//sectionscharclist.push_back("MEM_PRELOAD");
			if (!firstSection)
				featNodeAppend(head, "MEM_PRELOAD", 1.0);
			//printf("IMAGE_SCN_MEM_PRELOAD\n");
			break;
		}
		case IMAGE_SCN_ALIGN_1BYTES: {
			//sectionscharclist.push_back("ALIGN_1BYTES");
			if (!firstSection)
				featNodeAppend(head, "ALIGN_1BYTES", 1.0);
			//printf("IMAGE_SCN_ALIGN_1BYTES\n");
			break;
		}
		case IMAGE_SCN_ALIGN_2BYTES: {
			//sectionscharclist.push_back("ALIGN_2BYTES");
			if (!firstSection)
				featNodeAppend(head, "ALIGN_2BYTES", 1.0);
			//printf("IMAGE_SCN_ALIGN_2BYTES\n");
			break;
		}
		case IMAGE_SCN_ALIGN_4BYTES: {
			//sectionscharclist.push_back("ALIGN_4BYTES");
			if (!firstSection)
				featNodeAppend(head, "ALIGN_4BYTES", 1.0);
			//printf("IMAGE_SCN_ALIGN_4BYTES\n");
			break;
		}
		case IMAGE_SCN_ALIGN_8BYTES: {
			//sectionscharclist.push_back("ALIGN_8BYTES");
			if (!firstSection)
				featNodeAppend(head, "ALIGN_8BYTES", 1.0);
			//printf("IMAGE_SCN_ALIGN_8BYTES\n");
			break;
		}
		case IMAGE_SCN_ALIGN_16BYTES: {
			//sectionscharclist.push_back("ALIGN_16BYTES");
			if (!firstSection)
				featNodeAppend(head, "ALIGN_16BYTES", 1.0);
			//printf("IMAGE_SCN_ALIGN_16BYTES\n");
			break;
		}
		case IMAGE_SCN_ALIGN_32BYTES: {
			//sectionscharclist.push_back("ALIGN_32BYTES");
			if (!firstSection)
				featNodeAppend(head, "ALIGN_32BYTES", 1.0);
			//printf("IMAGE_SCN_ALIGN_32BYTES\n");
			break;
		}
		case IMAGE_SCN_ALIGN_64BYTES: {
			//sectionscharclist.push_back("ALIGN_64BYTES");
			if (!firstSection)
				featNodeAppend(head, "ALIGN_64BYTES", 1.0);
			//printf("IMAGE_SCN_ALIGN_64BYTES\n");
			break;
		}
		case IMAGE_SCN_ALIGN_128BYTES: {
			//sectionscharclist.push_back("ALIGN_128BYTES");
			if (!firstSection)
				featNodeAppend(head, "ALIGN_128BYTES", 1.0);
			//printf("IMAGE_SCN_ALIGN_128BYTES\n");
			break;
		}
		case IMAGE_SCN_ALIGN_256BYTES: {
			//sectionscharclist.push_back("ALIGN_256BYTES");
			if (!firstSection)
				featNodeAppend(head, "ALIGN_256BYTES", 1.0);
			//printf("IMAGE_SCN_ALIGN_256BYTES\n");
			break;
		}
		case IMAGE_SCN_ALIGN_512BYTES: {
			//sectionscharclist.push_back("ALIGN_512BYTES");
			if (!firstSection)
				featNodeAppend(head, "ALIGN_512BYTES", 1.0);
			//printf("IMAGE_SCN_ALIGN_512BYTES\n");
			break;
		}
		case IMAGE_SCN_ALIGN_1024BYTES: {
			//sectionscharclist.push_back("ALIGN_1024BYTES");
			if (!firstSection)
				featNodeAppend(head, "ALIGN_1024BYTES", 1.0);
			//printf("IMAGE_SCN_ALIGN_1024BYTES\n");
			break;
		}
		case IMAGE_SCN_ALIGN_2048BYTES: {
			//sectionscharclist.push_back("ALIGN_2048BYTES");
			if (!firstSection)
				featNodeAppend(head, "ALIGN_2048BYTES", 1.0);
			//printf("IMAGE_SCN_ALIGN_2048BYTES\n");
			break;
		}
		case IMAGE_SCN_ALIGN_4096BYTES: {
			//sectionscharclist.push_back("ALIGN_4096BYTES");
			if (!firstSection)
				featNodeAppend(head, "ALIGN_4096BYTES", 1.0);

			//printf("IMAGE_SCN_ALIGN_4096BYTES\n");
			break;
		}
		case IMAGE_SCN_ALIGN_8192BYTES: {
			//sectionscharclist.push_back("ALIGN_8192BYTES");
			if (!firstSection)
				featNodeAppend(head, "ALIGN_8192BYTES", 1.0);
			//printf("IMAGE_SCN_ALIGN_8192BYTES\n");
			break;
		}
		case IMAGE_SCN_LNK_NRELOC_OVFL: {
			//sectionscharclist.push_back("LNK_NRELOC_OVFL");
			if (!firstSection)
				featNodeAppend(head, "LNK_NRELOC_OVFL", 1.0);
			//printf("IMAGE_SCN_LNK_NRELOC_OVFL\n");
			break;
		}
		case IMAGE_SCN_MEM_DISCARDABLE: {
			//sectionscharclist.push_back("MEM_DISCARDABLE");
			if (!firstSection)
				featNodeAppend(head, "MEM_DISCARDABLE", 1.0);
			//printf("IMAGE_SCN_MEM_DISCARDABLE\n");
			break;
		}
		case IMAGE_SCN_MEM_NOT_CACHED: {
			//sectionscharclist.push_back("MEM_NOT_CACHED");
			if (!firstSection)
				featNodeAppend(head, "MEM_NOT_CACHED", 1.0);

			//printf("IMAGE_SCN_MEM_NOT_CACHED\n");
			break;
		}
		case IMAGE_SCN_MEM_NOT_PAGED: {
			//sectionscharclist.push_back("MEM_NOT_PAGED");
			if (!firstSection)
				featNodeAppend(head, "TYPE_NO_PAD", 1.0);

			//printf("IMAGE_SCN_MEM_NOT_PAGED\n");
			break;
		}
		case IMAGE_SCN_MEM_SHARED: {
			//sectionscharclist.push_back("MEM_SHARED");
			if (!firstSection)
				featNodeAppend(head, "MEM_SHARED", 1.0);

			//printf("IMAGE_SCN_MEM_SHARED\n");
			break;
		}
		case IMAGE_SCN_MEM_EXECUTE: {
			//sectionscharclist.push_back("MEM_EXECUTE");
			if (!firstSection)
				featNodeAppend(head, "MEM_EXECUTE", 1.0);

			//printf("IMAGE_SCN_MEM_EXECUTE\n");
			*MEM_EXECUTE_FLAG = 1;
			break;
		}
		case IMAGE_SCN_MEM_READ: {
			//sectionscharclist.push_back("MEM_READ");
			if (!firstSection)
				featNodeAppend(head, "MEM_READ", 1.0);

			//printf("IMAGE_SCN_MEM_READ\n");
			*MEM_READ_FLAG = 1;
			break;
		}
		case IMAGE_SCN_MEM_WRITE: {
			//sectionscharclist.push_back("MEM_WRITE");
			if (!firstSection)
				featNodeAppend(head, "MEM_WRITE", 1.0);
			*sectionW = *sectionW + 1;

			//printf("IMAGE_SCN_MEM_WRITE\n");
			//sectionW++;
			break;
		}
		default: {
			//featNodeAppend(head, "TYPE_NO_PAD", 1.0);
			//			printf("default\n");
			break;
		}
		}
	}
}

