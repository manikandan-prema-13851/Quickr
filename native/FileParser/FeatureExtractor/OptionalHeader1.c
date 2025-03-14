#include "OptionalHeader.h"
#include <stdio.h>
#include <Windows.h>
#include "FeatureHeader.h"


__declspec(noinline) void magicMapData(struct FeatNode** head, int switchcasevalue) {
	switch (switchcasevalue) {
	case 0x10b: {
		featNodeAppend(head, "PE32", 1.0);
		//printf("PE32\n");
		break;
	}
	case 0x20b: {
		featNodeAppend(head, "PE32_PLUS", 1.0);
		//printf("PE32_PLUS\n");
		break;
	}
	case 0x107: {
		featNodeAppend(head, "ROM", 1.0);
		//printf("ROM\n");
		break;
	}
	default:
		break;
	}

}


__declspec(noinline) void subSystemMapData(struct FeatNode** head, int switchcasevalue) {
	switch (switchcasevalue) {
	case IMAGE_SUBSYSTEM_UNKNOWN: {
		featNodeAppend(head, "UNKNOWN", 1.0);
		//printf("UNKNOWN\n");
		break;
	}
	case IMAGE_SUBSYSTEM_NATIVE: {
		featNodeAppend(head, "NATIVE", 1.0);
		//printf("NATIVE\n");
		break;
	}
	case IMAGE_SUBSYSTEM_WINDOWS_GUI: {
		featNodeAppend(head, "WINDOWS_GUI", 1.0);
		//printf("WINDOWS_GUI\n");
		break;
	}
	case IMAGE_SUBSYSTEM_WINDOWS_CUI: {
		featNodeAppend(head, "WINDOWS_CUI", 1.0);
		//printf("WINDOWS_CUI\n");
		break;
	}
	case IMAGE_SUBSYSTEM_OS2_CUI: {
		featNodeAppend(head, "OS2_CUI", 1.0);
		//printf("OS2_CUI\n");
		break;
	}
	case IMAGE_SUBSYSTEM_POSIX_CUI: {
		featNodeAppend(head, "POSIX_CUI", 1.0);
		//printf("POSIX_CUI\n");
		break;
	}
	case IMAGE_SUBSYSTEM_NATIVE_WINDOWS: {
		featNodeAppend(head, "NATIVE_WINDOWS", 1.0);
		//printf("NATIVE_WINDOWS\n");
		break;
	}
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: {
		featNodeAppend(head, "CE_GUI", 1.0);
		//printf("CE_GUI\n");
		break;
	}
	case IMAGE_SUBSYSTEM_EFI_APPLICATION: {
		featNodeAppend(head, "EFI_APPLICATION", 1.0);
		//printf("EFI_APPLICATION\n");
		break;
	}
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: {
		featNodeAppend(head, "EFI_BOOT_SERVICE_DRIVER", 1.0);
		//printf("EFI_BOOT_SERVICE_DRIVER\n");
		break;
	}
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: {
		featNodeAppend(head, "EFI_RUNTIME_DRIVER", 1.0);
		//printf("EFI_RUNTIME_DRIVER\n");
		break;
	}
	case IMAGE_SUBSYSTEM_EFI_ROM: {
		featNodeAppend(head, "EFI_ROM", 1.0);
		//printf("EFI_ROM\n");
		break;
	}
	case IMAGE_SUBSYSTEM_XBOX: {
		featNodeAppend(head, "XBOX", 1.0);
		//printf("XBOX\n");
		break;
	}
	case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: {
		featNodeAppend(head, "BOOT_APPLICATION", 1.0);
		//printf("BOOT_APPLICATION\n");
		break;
	}
	default:
		{
			break;
		}
	}
}


__declspec(noinline) void dllMapData(struct FeatNode** head, int switchcasevalue) {
	unsigned short int switchvalue = switchcasevalue;
	for (unsigned short int i = 0; i < 16; i++) {
		unsigned  short int subswitchcasevalue = (switchvalue) & (0x1 << i);
		switch (subswitchcasevalue) {

		case IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: {
			featNodeAppend(head, "HIGH_ENTROPY_VA", 1.0);
			//printf("HIGH_ENTROPY_VA\n\n");
			break;
		}
		case IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: {
			featNodeAppend(head, "DYNAMIC_BASE", 1.0);
			//printf("DYNAMIC_BASE\n\n");
			break;
		}
		case IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: {
			featNodeAppend(head, "FORCE_INTEGRITY", 1.0);
			//printf("FORCE_INTEGRITY\n\n");
			break;
		}
		case IMAGE_DLLCHARACTERISTICS_NX_COMPAT: {
			featNodeAppend(head, "NX_COMPAT", 1.0);
			//printf("NX_COMPAT\n\n");
			break;
		}
		case IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: {
			featNodeAppend(head, "NO_ISOLATION", 1.0);
			//printf("NO_ISOLATION\n\n");
			break;
		}
		case IMAGE_DLLCHARACTERISTICS_NO_SEH: {
			featNodeAppend(head, "NO_SEH", 1.0);
			//printf("NO_SEH\n\n");
			break;
		}
		case IMAGE_DLLCHARACTERISTICS_NO_BIND: {
			featNodeAppend(head, "NO_BIND", 1.0);
			//printf("NO_BIND\n\n");
			break;
		}
		case IMAGE_DLLCHARACTERISTICS_APPCONTAINER: {
			featNodeAppend(head, "APPCONTAINER", 1.0);
			//printf("APPCONTAINER\n\n");
			break;
		}
		case IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: {
			featNodeAppend(head, "WDM_DRIVER", 1.0);
			//printf("WDM_DRIVER\n\n");
			break;
		}
		case IMAGE_DLLCHARACTERISTICS_GUARD_CF: {
			featNodeAppend(head, "GUARD_CF", 1.0);
			//printf("GUARD_CF\n\n");
			break;
		}
		case IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: {
			featNodeAppend(head, "TERMINAL_SERVER_AWARE", 1.0);
			//printf("TERMINAL_SERVER_AWARE\n\n");
			break;
		}
		default: {
			break;
		}
		}
	}

}

