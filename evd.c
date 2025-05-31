#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)


typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;         // Handle to the module section
    PVOID MappedBase;       // Base address in memory
    PVOID ImageBase;        // Load address of the driver
    ULONG ImageSize;        // Size of the loaded module
    ULONG Flags;            // Flags (e.g., kernel mode module)
    USHORT LoadOrderIndex;  // Load order
    USHORT InitOrderIndex;  // Initialization order
    USHORT LoadCount;       // Reference count
    USHORT PathLength;      // Length of the driver path string
    CHAR FullPathName[256]; // Full module path
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;  // Total count of loaded drivers
    RTL_PROCESS_MODULE_INFORMATION Modules[1]; // Array of modules
} RTL_PROCESS_MODULES;


int main(int argc, char* argv[]) {

    //usual getting handle for undocumented function
        HMODULE hNtDll = GetModuleHandle("ntdll.dll");
    if (!hNtDll) {
        printf("Failed to load ntdll.dll\n");
        return 1;
    }

    //set the struct data from p* to actual Nt name that is = to the Nt name in the dll
    pNtQuerySystemInformation NtQuerySystemInformation =
        (pNtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        printf("Failed to get NtQueryInformationProcess\n");
        return 1;
    }

    //getting the size thats why NULL and 0 it saves as returnLen
    ULONG returnLen = 0;
    NTSTATUS status = NtQuerySystemInformation(11, NULL, 0, &returnLen);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        printf("Error 0x%X", status);
        return 1;
    }

    //alloc modules
    RTL_PROCESS_MODULES *modules = (RTL_PROCESS_MODULES*)malloc(returnLen);

    //actual call 
    status = NtQuerySystemInformation(11, modules, returnLen, &returnLen);
    if (status != STATUS_SUCCESS) {
        printf("Error 0x%X", status);
        return 1;
    }

    //printing # of modules from RTL_PROCESS_MODULES struct
    printf("Number of modules %lu\n", modules->NumberOfModules);

    //reading the file specified with argv[1] aka first arg
    FILE *file = fopen(argv[1], "a+");
    if (!file) {
        printf("Failed to open file\n");
    }

    char buffer[256];

  //added this becuase
    printf("Getting drivers");

    for (int i = 0; i < 5; i++) {
        printf(".");
        Sleep(200);
    }
    printf("\n");

  //bool for if vulnerable driver is found
    BOOL dirty = FALSE;
    
  //getting the names from the buffer
    while (fgets(buffer, sizeof(buffer), file)) {
        buffer[strcspn(buffer,"\n")] = '\0';
        for (int i=0; i < modules->NumberOfModules; i++) {
       
  //checking for vuln
        if (strstr(modules->Modules[i].FullPathName, buffer) != NULL) {
         printf("+ %s\n", modules->Modules[i].FullPathName);
        printf("Vulnerable Driver: %s - Bad driver found\n", (char*)modules->Modules[i].FullPathName);
        dirty = TRUE;
        }  
        }
    }

printf("+++++++++++++++++++++++++++++++\n");

//vuln check
if (dirty) {
    printf("Drivers: BAD\n");
} else {
    printf("Drivers: Clean\n");
}


    return 0;
}
