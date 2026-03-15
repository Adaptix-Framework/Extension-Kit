#include <windows.h>
#include <ntsecapi.h>
#include <winnetwk.h>
#include <lm.h>

void printoutput(BOOL done);
#include "base.c"


/* ADVAPI32 — LSA */
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaOpenPolicy(
    PLSA_UNICODE_STRING SystemName,
    PLSA_OBJECT_ATTRIBUTES ObjectAttributes,
    ACCESS_MASK DesiredAccess,
    PLSA_HANDLE PolicyHandle);

DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaLookupNames2(
    LSA_HANDLE PolicyHandle,
    ULONG Flags,
    ULONG Count,
    PLSA_UNICODE_STRING Names,
    PLSA_REFERENCED_DOMAIN_LIST *ReferencedDomains,
    PLSA_TRANSLATED_SID2 *Sids);

DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaClose(LSA_HANDLE ObjectHandle);
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaFreeMemory(PVOID Buffer);


DECLSPEC_IMPORT DWORD WINAPI MPR$WNetAddConnection2W(
    LPNETRESOURCEW lpNetResource,
    LPCWSTR lpPassword,
    LPCWSTR lpUserName,
    DWORD dwFlags);

DECLSPEC_IMPORT DWORD WINAPI MPR$WNetCancelConnection2W(
    LPCWSTR lpName,
    DWORD dwFlags,
    BOOL fForce);


DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenServiceA(
    SC_HANDLE hSCManager,
    LPCSTR    lpServiceName,
    DWORD     dwDesiredAccess);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$QueryServiceStatusEx(
    SC_HANDLE       hService,
    SC_STATUS_TYPE  InfoLevel,
    LPBYTE          lpBuffer,
    DWORD           cbBufSize,
    LPDWORD         pcbBytesNeeded);


static void record_match(const char *svc_name, const char *info, BOOL is_drv);

typedef struct { const char *name; const char *info; } SIG;

static const SIG SVC_SIGS[] = {

    /* AVG */
    {"avgsvc",                                        "AVG | AV Service | AV"},
    {"avgantivirus",                                  "AVG | Antivirus Service | AV"},

    /* Acronis */
    {"AcronisActiveProtectionService",                "Acronis | Active Protection Service | EPP"},

    /* AhnLab */
    {"v3svc",                                         "AhnLab | V3 Endpoint | AV"},
    {"asdsvc",                                        "AhnLab | ASD Service | AV"},

    /* Avast */
    {"avastsvc",                                      "Avast | AV Service | AV"},

    /* Avira */
    {"antivirservice",                                "Avira | AntiVir Service | AV"},
    {"avguard",                                       "Avira | Real-Time Protection | AV"},
    {"antivirscheduler",                              "Avira | Scheduler | AV"},

    /* Bitdefender */
    {"bdredline_agent",                               "Bitdefender | Agent RedLine Service | AV"},
    {"BDAuxSrv",                                      "Bitdefender | Auxiliary Service | AV"},
    {"UPDATESRV",                                     "Bitdefender | Desktop Update Service | AV"},
    {"VSSERV",                                        "Bitdefender | Virus Shield | AV"},
    {"bdredline",                                     "Bitdefender | RedLine Service | AV"},
    {"EPRedline",                                     "Bitdefender | Endpoint Redline Service | AV"},
    {"EPUpdateService",                               "Bitdefender | Endpoint Update Service | AV"},
    {"EPSecurityService",                             "Bitdefender | Endpoint Security Service | AV"},
    {"EPProtectedService",                            "Bitdefender | Endpoint Protected Service | AV"},
    {"EPIntegrationService",                          "Bitdefender | Endpoint Integration Service | AV"},
    {"epag",                                          "Bitdefender | GravityZone | EDR"},

    /* BlackBerry */
    {"cylancesvc",                                    "BlackBerry | Cylance PROTECT | EPP"},

    /* Broadcom */
    {"SepMasterService",                              "Broadcom | Symantec Endpoint Protection | EPP"},
    {"SepScanService",                                "Broadcom | Symantec Scan Services | EPP"},
    {"SNAC",                                          "Broadcom | Symantec Network Access Control | EPP"},
    {"sepwscsvc",                                     "Broadcom | SEP WSC Service | EPP"},
    {"ccsvchst",                                      "Broadcom | Symantec Endpoint Protection | EPP"},

    /* Carbon Black */
    {"Parity",                                        "Carbon Black | App Control Agent | EDR"},
    {"cbdefense",                                     "Carbon Black | Cloud Defense | EDR"},
    {"cbcomms",                                       "Carbon Black | Comms | EDR"},
    {"cbstream",                                      "Carbon Black | Streaming | EDR"},

    /* Check Point */
    {"CPDA",                                          "Check Point | Endpoint Agent | EPP"},
    {"vsmon",                                         "Check Point | Network Protection | EPP"},
    {"CPFileAnlyz",                                   "Check Point | File Analyzer | EPP"},
    {"EPClientUIService",                             "Check Point | Client UI Service | EPP"},
    {"epsecurity",                                    "Check Point | Endpoint Security | EPP"},
    {"mediapatcher",                                  "Check Point | Media Encryption | EPP"},
    {"tracsvrcalc",                                   "Check Point | Tracker Service | EPP"},

    /* Cisco */
    {"ciscoampsvc",                                   "Cisco | Secure Endpoint | EDR"},
    {"orbital",                                       "Cisco | Orbital Agent | EDR"},
    {"immunetprotect",                                "Cisco | Immunet Protect | EDR"},

    /* Comodo */
    {"cmdagent",                                      "Comodo | Agent Service | EPP"},

    /* CrowdStrike */
    {"CSFalconService",                               "CrowdStrike | Falcon Sensor Service | EDR"},
    {"csagent",                                       "CrowdStrike | Falcon Agent | EDR"},
    {"csfalconcontainer",                             "CrowdStrike | Falcon Container | EDR"},

    /* Cybereason */
    {"CybereasonActiveProbe",                         "Cybereason | Active Probe | EDR"},
    {"CybereasonCRS",                                 "Cybereason | Anti-Ransomware | EDR"},
    {"CybereasonBlocki",                              "Cybereason | Execution Prevention | EDR"},
    {"crssvc",                                        "Cybereason | Sensor | EDR"},

    /* Deep Instinct */
    {"deepinstinctsvc",                               "Deep Instinct | Agent | EDR"},

    /* Dr.Web */
    {"drwebservice",                                  "Dr.Web | Service | AV"},
    {"dwengine",                                      "Dr.Web | Scanning Engine | AV"},
    {"spideragent",                                   "Dr.Web | SpIDer Agent | AV"},

    /* ESET */
    {"ekm",                                           "ESET | ESET | AV"},
    {"epfw",                                          "ESET | ESET Firewall | AV"},
    {"epfwlwf",                                       "ESET | ESET LWF | AV"},
    {"epfwwfp",                                       "ESET | ESET WFP | AV"},
    {"EraAgentSvc",                                   "ESET | Management Agent | AV"},
    {"ERAAgent",                                      "ESET | ERA Agent | AV"},
    {"efwd",                                          "ESET | Forwarding Service | AV"},
    {"ehttpsrv",                                      "ESET | HTTP Server | AV"},
    {"ekrn",                                          "ESET | Kernel Service | AV"},
    {"eei_agent",                                     "ESET | Inspect Agent | EDR"},
    {"essvc",                                         "ESET | Security Service | AV"},

    /* Elastic */
    {"elastic-agent",                                 "Elastic | Elastic Agent | EDR"},
    {"Elastic Agent",                                 "Elastic | Elastic Agent | EDR"},
    {"ElasticEndpoint",                               "Elastic | Elastic Endpoint | EDR"},
    {"Elastic Endpoint",                              "Elastic | Elastic Endpoint | EDR"},
    {"elastic-endpoint",                              "Elastic | Elastic Endpoint | EDR"},
    {"filebeat",                                      "Elastic | Filebeat | Telemetry"},
    {"winlogbeat",                                    "Elastic | Winlogbeat | Telemetry"},

    /* Emsisoft */
    {"a2service",                                     "Emsisoft | Anti-Malware Service | AV"},
    {"a2guard",                                       "Emsisoft | Behavior Blocker | AV"},

    /* Fortinet */
    {"FA_Scheduler",                                  "Fortinet | FortiClient Scheduler | EPP"},
    {"FCT_SecSvr",                                    "Fortinet | FortiClient Protected | EPP"},
    {"FortiEDR Collector Service",                    "Fortinet | FortiEDR Collector | EDR"},
    {"forticlientmon",                                "Fortinet | FortiClient Monitor | EPP"},
    {"forticollector",                                "Fortinet | FortiEDR Collector | EDR"},
    {"fortiedr",                                      "Fortinet | FortiEDR | EDR"},

    /* G Data */
    {"AVKWCtl",                                       "G Data | AV Kit Window Control | AV"},
    {"AVKProxy",                                      "G Data | AntiVirus Proxy | AV"},
    {"GDScan",                                        "G Data | AntiVirus Scan | AV"},
    {"gdsc",                                          "G Data | Security Client | AV"},
    {"gdfsvc",                                        "G Data | File Server Security | AV"},

    /* HarfangLab */
    {"hurukai",                                       "HarfangLab | EDR Agent | EDR"},

    /* Huntress */
    {"huntressagent",                                 "Huntress | Agent | EDR"},

    /* Ivanti */
    {"STAgent$Shavlik Protect",                       "Ivanti | Security Controls Agent | EPP"},
    {"STDispatch$Shavlik Protect",                    "Ivanti | Security Controls Dispatcher | EPP"},

    /* Kaspersky */
    {"kavfsslp",                                      "Kaspersky | Exploit Prevention Service | AV"},
    {"KAVFS",                                         "Kaspersky | Security Service | AV"},
    {"KAVFSGT",                                       "Kaspersky | Security Management Service | AV"},
    {"klnagent",                                      "Kaspersky | Network Agent | AV"},
    {"avp",                                           "Kaspersky | Endpoint Security | AV"},

    /* LimaCharlie */
    {"rphcpsvc",                                      "LimaCharlie | Sensor | EDR"},

    /* Malwarebytes */
    {"MBAMService",                                   "Malwarebytes | Service | AV"},
    {"MBEndpointAgent",                               "Malwarebytes | Cloud Endpoint Agent | AV"},

    /* Microsoft */
    {"WinDefend",                                     "Microsoft | Windows Defender AV | AV"},
    {"Sense",                                         "Microsoft | Defender for Endpoint | EDR"},
    {"WdNisSvc",                                      "Microsoft | Defender Network Inspection | AV"},
    {"mdcoresvc",                                     "Microsoft | Defender Core | AV"},
    {"mpssvc",                                        "Microsoft | Defender Firewall | AV"},
    {"wscsvc",                                        "Microsoft | Security Center | AV"},
    {"securityhealthservice",                         "Microsoft | Security Health | AV"},
    {"sysmon",                                        "Microsoft | Sysmon | Telemetry"},
    {"sysmon64",                                      "Microsoft | Sysmon 64 | Telemetry"},
    {"webthreatdefsvc",                               "Microsoft | Web Threat Defense | AV"},
    {"webthreatdefusersvc",                           "Microsoft | Web Threat Defense User | AV"},

    /* Norton */
    {"navapsvc",                                      "Norton | Auto-Protect | AV"},
    {"nsservice",                                     "Norton | Security Service | AV"},
    {"nswocsvc",                                      "Norton | WSC Service | AV"},

    /* Palo Alto */
    {"xdrhealth",                                     "Palo Alto | Cortex XDR Health Helper | EDR"},
    {"cyserver",                                      "Palo Alto | Cortex XDR | EDR"},
    {"cyverasvc",                                     "Palo Alto | Cortex XDR Cyvera | EDR"},
    {"trapssvc",                                      "Palo Alto | Traps Service | EDR"},

    /* Panda */
    {"PandaAetherAgent",                              "Panda | Endpoint Agent | EPP"},
    {"PSUAService",                                   "Panda | Product Service | EPP"},
    {"NanoServiceMain",                               "Panda | Cloud Antivirus Service | EPP"},

    /* Qualys */
    {"qualysagent",                                   "Qualys | Cloud Agent | Vuln Scanner"},

    /* Rapid7 */
    {"ir_agent",                                      "Rapid7 | Insight Agent | EDR"},

    /* SentinelOne */
    {"SentinelAgent",                                 "SentinelOne | Endpoint Agent | EDR"},
    {"SentinelStaticEngine",                          "SentinelOne | Static Engine | EDR"},
    {"LogProcessorService",                           "SentinelOne | Log Processor | EDR"},

    /* Sophos */
    {"SntpService",                                   "Sophos | Network Threat Protection | EDR"},
    {"Sophos Endpoint Defense Service",               "Sophos | Endpoint Defense Service | EDR"},
    {"Sophos File Scanner Service",                   "Sophos | File Scanner Service | EDR"},
    {"Sophos Health Service",                         "Sophos | Health Service | EDR"},
    {"Sophos Live Query",                             "Sophos | Live Query | EDR"},
    {"Sophos Managed Threat Response",                "Sophos | Managed Threat Response | EDR"},
    {"Sophos MCS Agent",                              "Sophos | MCS Agent | EDR"},
    {"Sophos MCS Client",                             "Sophos | MCS Client | EDR"},
    {"Sophos System Protection Service",              "Sophos | System Protection Service | EDR"},
    {"sophossps",                                     "Sophos | Endpoint | EPP"},
    {"sophosfilescanner",                             "Sophos | File Scanner | AV"},
    {"sophoshealth",                                  "Sophos | Health Service | EPP"},
    {"hmpalert",                                      "Sophos | HitmanPro Alert | EDR"},
    {"sophosagent",                                   "Sophos | Management Agent | EPP"},
    {"sophosntpservice",                              "Sophos | Network Threat Protection | EPP"},
    {"savservice",                                    "Sophos | SAV Service | AV"},

    /* Splunk */
    {"splunkforwarder",                               "Splunk | Forwarder | Telemetry"},

    /* Tanium */
    {"taniumclient",                                  "Tanium | Client | EPP"},
    {"taniumdetect",                                  "Tanium | Detect | EDR"},

    /* Trellix */
    {"McAfee Endpoint Security Platform Service",     "Trellix | Core Service | EDR"},
    {"mfemactl",                                      "Trellix | Management Service | EDR"},
    {"mfemms",                                        "Trellix | McAfee Management | EDR"},
    {"mfefire",                                       "Trellix | Firewall Core | EDR"},
    {"masvc",                                         "Trellix | Agent Service | EDR"},
    {"macmnsvc",                                      "Trellix | Agent Common Service | EDR"},
    {"mfetp",                                         "Trellix | Threat Prevention | EDR"},
    {"mfewc",                                         "Trellix | Web Control | EDR"},
    {"mfeaack",                                       "Trellix | Anti-Malware Core | EDR"},
    {"xagt",                                          "Trellix | FireEye HX | EDR"},
    {"firesvc",                                       "Trellix | FireEye HX Agent | EDR"},
    {"mfeesp",                                        "Trellix | McAfee Endpoint Security | EPP"},

    /* Trend Micro */
    {"Trend Micro Endpoint Basecamp",                 "Trend Micro | Endpoint Basecamp | EDR"},
    {"TMBMServer",                                    "Trend Micro | Unauthorized Change Prevention | EDR"},
    {"Trend Micro Web Service Communicator",          "Trend Micro | Web Service Communicator | EDR"},
    {"TMiACAgentSvc",                                 "Trend Micro | Application Control | EDR"},
    {"CETASvc",                                       "Trend Micro | Cloud Endpoint Telemetry | EDR"},
    {"iVPAgent",                                      "Trend Micro | Vulnerability Protection | EDR"},
    {"ds_agent",                                      "Trend Micro | Deep Security Agent | EDR"},
    {"ds_monitor",                                    "Trend Micro | Deep Security Monitor | EDR"},
    {"ds_notifier",                                   "Trend Micro | Deep Security Notifier | EDR"},
    {"coreserviceshell",                              "Trend Micro | Apex One | EDR"},
    {"tmlisten",                                      "Trend Micro | Listener | EPP"},
    {"tmntsrv",                                       "Trend Micro | OfficeScan NT | AV"},
    {"tmbmsrv",                                       "Trend Micro | Unauthorized Change Prevention | EPP"},

    /* VIPRE */
    {"sbamsvc",                                       "VIPRE | Anti-Malware Service | AV"},

    /* Velociraptor */
    {"velociraptor",                                  "Velociraptor | Agent | DFIR"},

    /* WatchGuard */
    {"psanhost",                                      "WatchGuard | Panda Endpoint | EPP"},

    /* Wazuh */
    {"wazuhsvc",                                      "Wazuh | Agent | SIEM-EDR"},
    {"ossecagent",                                    "Wazuh | OSSEC Agent | SIEM-EDR"},

    /* Webroot */
    {"wrsa",                                          "Webroot | SecureAnywhere | AV"},

    /* WithSecure */
    {"fsdevcon",                                      "WithSecure | Device Control | AV"},
    {"fshoster",                                      "WithSecure | Hoster | AV"},
    {"fsnethoster",                                   "WithSecure | Hoster Restricted | AV"},
    {"fsulhoster",                                    "WithSecure | Ultralight Hoster | AV"},
    {"fsulnethoster",                                 "WithSecure | Ultralight Network Hoster | AV"},
    {"fsulprothoster",                                "WithSecure | Ultralight Protected Hoster | AV"},
    {"wsulavprohoster",                               "WithSecure | Ultralight Protected AV Hoster | AV"},
    {"fsav32",                                        "WithSecure | F-Secure AV | AV"},
    {"fsgk32",                                        "WithSecure | F-Secure GateKeeper | AV"},

    /* Zscaler */
    {"zscalerservice",                                "Zscaler | Client Connector | ZTNA"},
    {"ztunnel",                                       "Zscaler | Tunnel Service | ZTNA"},
    {NULL, NULL}
};

static const SIG DRV_SIGS[] = {

    /* AhnLab */
    {"ahksvr",                                        "AhnLab | Hook Server Driver | AV"},
    {"v3flt2k",                                       "AhnLab | V3 Filter Driver | AV"},
    {"v3monitor",                                     "AhnLab | V3 Endpoint Monitor | AV"},

    /* Avast */
    {"aswarpt",                                       "Avast | Anti-Rootkit Driver | AV"},
    {"aswbidsdriver",                                 "Avast | Behavior Shield Driver | AV"},
    {"aswbidsha",                                     "Avast | Behavior Shield A | AV"},
    {"aswelam",                                       "Avast | ELAM Driver | AV"},
    {"aswmonflt",                                     "Avast | Monitor Minifilter | AV"},
    {"aswsnx",                                        "Avast | Virtualization Driver | AV"},
    {"aswsp",                                         "Avast | Self-Protection Driver | AV"},
    {"aswstm",                                        "Avast | Stream Filter | AV"},

    /* Avira */
    {"avgntflt",                                      "Avira | Network Filter Driver | AV"},
    {"avipbb",                                        "Avira | IP Blocker Bridge | AV"},
    {"avkmgr",                                        "Avira | AV Kernel Manager | AV"},

    /* Bitdefender */
    {"avckf",                                         "Bitdefender | AV Callback Filter | AV"},
    {"bddevflt",                                      "Bitdefender | Device Filter | AV"},
    {"bdelam",                                        "Bitdefender | ELAM Driver | AV"},
    {"bdfndisf",                                      "Bitdefender | Network Filter | AV"},
    {"bdfwfpf",                                       "Bitdefender | WFP Firewall Filter | AV"},
    {"bdselfpr",                                      "Bitdefender | Self-Protection Driver | EDR"},
    {"gzflt",                                         "Bitdefender | GravityZone Minifilter | EDR"},
    {"trufos",                                        "Bitdefender | Scanning Driver | AV"},

    /* BlackBerry */
    {"cylancedrv",                                    "BlackBerry | Cylance Kernel Driver | EPP"},

    /* Broadcom */
    {"bhdrvx64",                                      "Broadcom | Symantec SONAR Driver | EPP"},
    {"srtsp",                                         "Broadcom | Symantec Real-Time SP | AV"},
    {"srtspx",                                        "Broadcom | SEP Real-Time SP | AV"},
    {"symefa",                                        "Broadcom | Symantec Extended File Attrs | EPP"},
    {"symefasi",                                      "Broadcom | Symantec FS Monitor | EPP"},
    {"symevent",                                      "Broadcom | Symantec Event Driver | EPP"},

    /* Carbon Black */
    {"carbonblackk",                                  "Carbon Black | Kernel Driver | EDR"},
    {"cbk7",                                          "Carbon Black | Kernel Module | EDR"},
    {"cticomms",                                      "Carbon Black | Comms Driver | EDR"},
    {"ctifile",                                       "Carbon Black | File Filter | EDR"},

    /* Check Point */
    {"cpprotect",                                     "Check Point | SandBlast Protection Driver | EDR"},
    {"epklib",                                        "Check Point | Endpoint Kernel Library | EPP"},

    /* Cisco */
    {"immunetprotect",                                "Cisco | Secure Endpoint Protection | EDR"},
    {"immunetselfprotect",                            "Cisco | Secure Endpoint Self-Protection | EDR"},
    {"isedrv",                                        "Cisco | ISE Posture Driver | EPP"},

    /* Comodo */
    {"cmdguard",                                      "Comodo | Guard Driver | EPP"},
    {"cmdhlp",                                        "Comodo | Helper Driver | EPP"},
    {"inspect",                                       "Comodo | File Inspection Driver | EPP"},

    /* CrowdStrike */
    {"csagent",                                       "CrowdStrike | Falcon Kernel Driver | EDR"},
    {"csboot",                                        "CrowdStrike | Falcon Boot Driver | EDR"},
    {"csdevicecontrol",                               "CrowdStrike | Device Control Driver | EDR"},

    /* CyberArk */
    {"cybkerneltracker",                              "CyberArk | Kernel Tracker Driver | EPP"},

    /* Cybereason */
    {"psycheddriver",                                 "Cybereason | Kernel Driver | EDR"},
    {"psychedfilterdriver",                           "Cybereason | Minifilter Driver | EDR"},

    /* Deep Instinct */
    {"deepinstinctdrv",                               "Deep Instinct | Kernel Driver | EDR"},

    /* Dr.Web */
    {"dwprot",                                        "Dr.Web | Protection Driver | AV"},

    /* ESET */
    {"eamonm",                                        "ESET | File System Monitor | AV"},
    {"edevmon",                                       "ESET | Device Monitor | AV"},
    {"eelam",                                         "ESET | ELAM Driver | AV"},
    {"ehdrv",                                         "ESET | Helper Driver | AV"},
    {"ekbdflt",                                       "ESET | Keyboard Filter | AV"},
    {"epfw",                                          "ESET | Firewall Driver | AV"},
    {"epfwwfp",                                       "ESET | Firewall WFP Driver | AV"},

    /* Elastic */
    {"elasticendpoint",                               "Elastic | Endpoint Driver | EDR"},

    /* Emsisoft */
    {"a2accx64",                                      "Emsisoft | Access Filter (x64) | AV"},
    {"a2dskm",                                        "Emsisoft | Disk Monitor Driver | AV"},

    /* Endgame */
    {"esensor",                                       "Endgame | Sensor Driver | EDR"},

    /* Fortinet */
    {"fdedrdrv",                                      "Fortinet | FortiEDR Kernel Driver | EDR"},
    {"fortimon",                                      "Fortinet | FortiClient Monitor Driver | EPP"},
    {"fortishield",                                   "Fortinet | FortiEDR Shield Driver | EDR"},

    /* G Data */
    {"gddisk",                                        "G Data | Disk Filter | AV"},
    {"gdkbflt64",                                     "G Data | Kernel Block Filter | AV"},

    /* Huntress */
    {"huntressdrv",                                   "Huntress | Kernel Driver | EDR"},

    /* Kaspersky */
    {"klam",                                          "Kaspersky | Anti-Malware Filter | AV"},
    {"klbackupdisk",                                  "Kaspersky | Backup Disk Filter | AV"},
    {"klboot",                                        "Kaspersky | Boot Driver | AV"},
    {"kldisk",                                        "Kaspersky | Disk Filter | AV"},
    {"klelam",                                        "Kaspersky | ELAM Driver | AV"},
    {"klhk",                                          "Kaspersky | Hook Driver | AV"},
    {"klif",                                          "Kaspersky | Interceptor Filter | AV"},
    {"kltdi",                                         "Kaspersky | TDI Driver | AV"},
    {"klwfp",                                         "Kaspersky | WFP Callout Driver | AV"},
    {"kneps",                                         "Kaspersky | Network Protection | AV"},

    /* Malwarebytes */
    {"farflt",                                        "Malwarebytes | File System Monitor | AV"},
    {"mbam",                                          "Malwarebytes | Anti-Malware Driver | AV"},
    {"mbamswissarmy",                                 "Malwarebytes | Swiss Army Kernel Driver | AV"},

    /* Microsoft */
    {"mssecflt",                                      "Microsoft | Defender for Endpoint Minifilter | EDR"},
    {"sysmondrv",                                     "Microsoft | Sysmon Driver | Telemetry"},
    {"wdboot",                                        "Microsoft | Defender Boot Driver | AV"},
    {"wdfilter",                                      "Microsoft | Defender Minifilter | AV"},
    {"wdnisdrv",                                      "Microsoft | Defender NIS Driver | AV"},

    /* Nexthink */
    {"nxtrdrv",                                       "Nexthink | Endpoint Driver | Telemetry"},

    /* Norton */
    {"naveng",                                        "Norton | NAV Engine | AV"},
    {"navex",                                         "Norton | NAV Extraction | AV"},
    {"symds",                                         "Norton | Symantec DS Driver | AV"},
    {"symnets",                                       "Norton | Symantec Network Security | AV"},

    /* Palo Alto */
    {"cyverak",                                       "Palo Alto | Cortex XDR Kernel Driver | EDR"},
    {"cyvrfsfd",                                      "Palo Alto | Cortex XDR FS Filter | EDR"},
    {"tladriver",                                     "Palo Alto | Cortex XDR TLA Driver | EDR"},

    /* Secureworks */
    {"groundling64",                                  "Secureworks | Red Cloak Driver (x64) | EDR"},

    /* SentinelOne */
    {"sentineldevicecontrol",                         "SentinelOne | Device Control Driver | EDR"},
    {"sentinelelam",                                  "SentinelOne | ELAM Driver | EDR"},
    {"sentinelmonitor",                               "SentinelOne | Kernel Monitor | EDR"},
    {"sentinelnetworkmonitor",                        "SentinelOne | Network Monitor Driver | EDR"},

    /* Sophos */
    {"hmpalert",                                      "Sophos | HitmanPro.Alert Driver | EDR"},
    {"safestorefilter",                               "Sophos | SafeStore Filter | EPP"},
    {"savonaccess",                                   "Sophos | On-Access Filter | AV"},
    {"sdcfilter",                                     "Sophos | Data Control Filter | EPP"},
    {"sophosed",                                      "Sophos | Endpoint Defense Driver | EPP"},
    {"sophosntpflt",                                  "Sophos | NTP Minifilter | EPP"},

    /* Tanium */
    {"taniumrecorderdrv",                             "Tanium | Recorder Kernel Driver | Telemetry"},

    /* Trellix */
    {"fekern",                                        "Trellix | FireEye Kernel Driver | EDR"},
    {"hxdriver",                                      "Trellix | FireEye HX Kernel Driver | EDR"},
    {"mfeaskm",                                       "Trellix | McAfee Anti-Stealth Kernel | EPP"},
    {"mfeavfk",                                       "Trellix | McAfee AV Filter Kernel | AV"},
    {"mfefirek",                                      "Trellix | McAfee Firewall Kernel | EPP"},
    {"mfehidk",                                       "Trellix | McAfee HIPS IDS Kernel | EPP"},
    {"mfencbdc",                                      "Trellix | McAfee Network Control | EPP"},
    {"mfencfilter",                                   "Trellix | McAfee Network Content Filter | EPP"},
    {"mfewfpk",                                       "Trellix | McAfee WFP Kernel | EPP"},
    {"wfp_mrt",                                       "Trellix | FireEye WFP MRT Driver | EDR"},

    /* Trend Micro */
    {"tmactmon",                                      "Trend Micro | Activity Monitor Driver | EDR"},
    {"tmcomm",                                        "Trend Micro | Common Module Driver | EPP"},
    {"tmebc",                                         "Trend Micro | Exploit Block Driver | EDR"},
    {"tmevtmgr",                                      "Trend Micro | Event Manager Driver | EDR"},
    {"tmtdi",                                         "Trend Micro | TDI Driver | EPP"},
    {"tmumh",                                         "Trend Micro | UMH Driver | EPP"},
    {"tmxpflt",                                       "Trend Micro | Cross-Platform Minifilter | EDR"},

    /* VIPRE */
    {"sbredrv",                                       "VIPRE | Kernel Driver | AV"},

    /* WatchGuard */
    {"psinfile",                                      "WatchGuard | Panda File Filter | EPP"},
    {"psinproc",                                      "WatchGuard | Panda Process Filter | EPP"},
    {"pskmad",                                        "WatchGuard | Panda Kernel Monitor | EPP"},

    /* Webroot */
    {"wrkrn",                                         "Webroot | Kernel Driver | AV"},

    /* WithSecure */
    {"fsatp",                                         "WithSecure | F-Secure ATP Driver | EDR"},
    {"fsdfw",                                         "WithSecure | F-Secure Firewall Driver | AV"},
    {"fses",                                          "WithSecure | F-Secure Endpoint Driver | AV"},
    {"fshs",                                          "WithSecure | F-Secure HS Driver | AV"},
    {"xfsgk",                                         "WithSecure | F-Secure GateKeeper Driver | AV"},

    /* Zscaler */
    {"zscalertun",                                    "Zscaler | Tunnel Driver | ZTNA"},
    {NULL, NULL}
};

#define HEAP KERNEL32$GetProcessHeap()

static void mb_to_wc(const char *src, wchar_t *dst, int dstlen) {
    KERNEL32$MultiByteToWideChar(CP_ACP, 0, src, -1, dst, dstlen);
}

static void wc_to_mb(const wchar_t *src, char *dst, int dstlen) {
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, src, -1, dst, dstlen, NULL, NULL);
}


static int ci_eq(const char *a, const char *b) {
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}


static int lsar_check_service(LSA_HANDLE hPolicy, const char *svcname) {
    wchar_t namebuf[256];
    wchar_t fullname[280];

    mb_to_wc("NT Service\\", fullname, 16);
    mb_to_wc(svcname, namebuf, 256);
    MSVCRT$wcscat(fullname, namebuf);

    LSA_UNICODE_STRING lsaName;
    lsaName.Buffer        = fullname;
    lsaName.Length        = (USHORT)(MSVCRT$wcslen(fullname) * sizeof(wchar_t));
    lsaName.MaximumLength = lsaName.Length + sizeof(wchar_t);

    PLSA_REFERENCED_DOMAIN_LIST pDomains = NULL;
    PLSA_TRANSLATED_SID2        pSids    = NULL;

    NTSTATUS st = ADVAPI32$LsaLookupNames2(
        hPolicy, 0, 1, &lsaName, &pDomains, &pSids);

    if (pDomains) ADVAPI32$LsaFreeMemory(pDomains);
    if (pSids)    ADVAPI32$LsaFreeMemory(pSids);

    return (st == 0 || st == 0x00000107);
}

static int phase_lsar_services(LSA_HANDLE hPolicy,
                               int *out_edr, int *out_av,
                               int *out_telemetry, int *out_epp)
{
    int found = 0;

    internal_printf("\n[*] Checking installed services via LsarLookupNames...\n");

    for (int i = 0; SVC_SIGS[i].name != NULL; i++) {
        if (lsar_check_service(hPolicy, SVC_SIGS[i].name)) {
            const char *info = SVC_SIGS[i].info;

            /* Extract category (3rd field: "Vendor | Product | CAT") */
            const char *p1 = MSVCRT$strstr(info, " | ");
            const char *cat = NULL;
            if (p1) {
                const char *p2 = MSVCRT$strstr(p1 + 3, " | ");
                if (p2) cat = p2 + 3;
            }

            if (cat && MSVCRT$_stricmp(cat, "EDR") == 0) {
                internal_printf("  [INSTALLED][EDR] %s  (svc: %s)\n", info, SVC_SIGS[i].name);
                *out_edr = 1;
            } else if (cat && MSVCRT$_stricmp(cat, "AV") == 0) {
                internal_printf("  [INSTALLED][AV ] %s  (svc: %s)\n", info, SVC_SIGS[i].name);
                *out_av = 1;
            } else if (cat && (MSVCRT$_stricmp(cat, "Telemetry") == 0 ||
                               MSVCRT$_stricmp(cat, "SIEM-EDR") == 0  ||
                               MSVCRT$_stricmp(cat, "DFIR") == 0)) {
                internal_printf("  [INSTALLED][TEL] %s  (svc: %s)\n", info, SVC_SIGS[i].name);
                *out_telemetry = 1;
            } else if (cat && MSVCRT$_stricmp(cat, "EPP") == 0) {
                internal_printf("  [INSTALLED][EPP] %s  (svc: %s)\n", info, SVC_SIGS[i].name);
                *out_epp = 1;
            } else {
                /* ZTNA, Vuln Scanner, etc. — cuenta como EPP para threat level */
                internal_printf("  [INSTALLED][OTH] %s  (svc: %s)\n", info, SVC_SIGS[i].name);
                *out_epp = 1;
            }
            found++;
            record_match(SVC_SIGS[i].name, info, FALSE);
        }
    }

    if (found == 0)
        internal_printf("  (none matched)\n");

    return found;
}

static int phase_scm_drivers(const char *target_mb,
                              int *out_edr, int *out_av,
                              int *out_telemetry, int *out_epp)
{
    int found = 0;

    internal_printf("\n[*] Checking kernel drivers via remote SCM...\n");

    SC_HANDLE hScm = ADVAPI32$OpenSCManagerA(
        target_mb,          
        NULL,               
        SC_MANAGER_ENUMERATE_SERVICE);

    if (!hScm) {
        DWORD err = KERNEL32$GetLastError();
        internal_printf("  [-] OpenSCManagerA failed (err: %lu)  need SC_MANAGER_ENUMERATE_SERVICE\n", err);
        return -1;
    }

    DWORD bytesNeeded  = 0;
    DWORD svcReturned  = 0;
    DWORD resumeHandle = 0;
    BOOL  more_data    = TRUE;

    while (more_data) {

        ADVAPI32$EnumServicesStatusExA(
            hScm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER,
            SERVICE_STATE_ALL,
            NULL, 0,
            &bytesNeeded,
            &svcReturned,
            &resumeHandle,
            NULL);

        if (bytesNeeded == 0) break;

        LPBYTE buf = (LPBYTE)MSVCRT$calloc(bytesNeeded + 256, 1);
        if (!buf) break;

        DWORD thisBatch = 0;
        BOOL ok = ADVAPI32$EnumServicesStatusExA(
            hScm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER,
            SERVICE_STATE_ALL,
            buf, bytesNeeded + 256,
            &bytesNeeded,
            &thisBatch,
            &resumeHandle,
            NULL);

        DWORD err = KERNEL32$GetLastError();
        more_data = (!ok && err == ERROR_MORE_DATA);

        ENUM_SERVICE_STATUS_PROCESSA *entries = (ENUM_SERVICE_STATUS_PROCESSA *)buf;

        for (DWORD i = 0; i < thisBatch; i++) {
            const char *drv_name = entries[i].lpServiceName;

            for (int j = 0; DRV_SIGS[j].name != NULL; j++) {
                if (MSVCRT$_stricmp(drv_name, DRV_SIGS[j].name) != 0)
                    continue;

                const char *info = DRV_SIGS[j].info;
                const char *p1   = MSVCRT$strstr(info, " | ");
                const char *cat  = NULL;
                if (p1) {
                    const char *p2 = MSVCRT$strstr(p1 + 3, " | ");
                    if (p2) cat = p2 + 3;
                }

                if (cat && MSVCRT$_stricmp(cat, "EDR") == 0) {
                    internal_printf("  [INSTALLED][EDR] %s  (drv: %s)\n", info, drv_name);
                    *out_edr = 1;
                } else if (cat && MSVCRT$_stricmp(cat, "AV") == 0) {
                    internal_printf("  [INSTALLED][AV ] %s  (drv: %s)\n", info, drv_name);
                    *out_av = 1;
                } else if (cat && (MSVCRT$_stricmp(cat, "Telemetry") == 0 ||
                                   MSVCRT$_stricmp(cat, "SIEM-EDR") == 0  ||
                                   MSVCRT$_stricmp(cat, "DFIR") == 0)) {
                    internal_printf("  [INSTALLED][TEL] %s  (drv: %s)\n", info, drv_name);
                    *out_telemetry = 1;
                } else if (cat && MSVCRT$_stricmp(cat, "EPP") == 0) {
                    internal_printf("  [INSTALLED][EPP] %s  (drv: %s)\n", info, drv_name);
                    *out_epp = 1;
                } else {
                    internal_printf("  [INSTALLED][OTH] %s  (drv: %s)\n", info, drv_name);
                }
                found++;
                record_match(DRV_SIGS[j].name, info, TRUE);
                break;
            }
        }

        MSVCRT$free(buf);


        if (ok) break;
    }
    ADVAPI32$CloseServiceHandle(hScm);

    if (found == 0)
        internal_printf("  (none matched)\n");

    return found;
}

#define MAX_MATCHES 64

typedef struct {
    const char *svc_name;
    const char *info;
    BOOL        is_drv;
} MATCH_ENTRY;

static MATCH_ENTRY g_matches[MAX_MATCHES];
static int         g_match_count = 0;

static void record_match(const char *svc_name, const char *info, BOOL is_drv)
{
    if (g_match_count >= MAX_MATCHES) return;
    g_matches[g_match_count].svc_name = svc_name;
    g_matches[g_match_count].info     = info;
    g_matches[g_match_count].is_drv   = is_drv;
    g_match_count++;
}

static void phase_scm_status(const char *target_mb)
{
    if (g_match_count == 0) return;

    internal_printf("\n[*] Querying service status via SCM...\n");

    /* SC_MANAGER_CONNECT — lowest privilege, any authenticated user */
    SC_HANDLE hScm = ADVAPI32$OpenSCManagerA(
        target_mb,
        NULL,
        SC_MANAGER_CONNECT);

    if (!hScm) {
        internal_printf("  [x] OpenSCManagerA failed (err: %lu)\n", KERNEL32$GetLastError());
        return;
    }

    int running = 0;
    int stopped = 0;

    for (int i = 0; i < g_match_count; i++) {
        const char *svc_name = g_matches[i].svc_name;
        const char *info     = g_matches[i].info;
        const char *tag      = g_matches[i].is_drv ? "drv" : "svc";

        /* Extraer categoría de "Vendor | Product | CAT" */
        const char *p1  = MSVCRT$strstr(info, " | ");
        const char *cat = NULL;
        if (p1) {
            const char *p2 = MSVCRT$strstr(p1 + 3, " | ");
            if (p2) cat = p2 + 3;
        }
        const char *cat_tag = "OTH";
        if (cat) {
            if      (MSVCRT$_stricmp(cat, "EDR") == 0)                    cat_tag = "EDR";
            else if (MSVCRT$_stricmp(cat, "AV") == 0)                     cat_tag = "AV ";
            else if (MSVCRT$_stricmp(cat, "EPP") == 0)                    cat_tag = "EPP";
            else if (MSVCRT$_stricmp(cat, "Telemetry") == 0 ||
                     MSVCRT$_stricmp(cat, "SIEM-EDR") == 0  ||
                     MSVCRT$_stricmp(cat, "DFIR") == 0)                    cat_tag = "TEL";
        }

        SC_HANDLE hSvc = ADVAPI32$OpenServiceA(
            hScm,
            svc_name,
            SERVICE_QUERY_STATUS);

        if (!hSvc) {

            continue;
        }

        SERVICE_STATUS_PROCESS ssp;
        DWORD dwBytesNeeded = 0;
        BOOL ok = ADVAPI32$QueryServiceStatusEx(
            hSvc,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&ssp,
            sizeof(ssp),
            &dwBytesNeeded);

        ADVAPI32$CloseServiceHandle(hSvc);

        if (!ok) continue;

        if (ssp.dwCurrentState == SERVICE_RUNNING) {
            internal_printf("  [RUNNING ][%s] %s  (%s: %s)\n", cat_tag, info, tag, svc_name);
            running++;
        } else {
            const char *state_str = "STOPPED";
            switch (ssp.dwCurrentState) {
                case SERVICE_STOPPED:          state_str = "STOPPED";          break;
                case SERVICE_START_PENDING:    state_str = "START_PENDING";    break;
                case SERVICE_STOP_PENDING:     state_str = "STOP_PENDING";     break;
                case SERVICE_PAUSED:           state_str = "PAUSED";           break;
                case SERVICE_PAUSE_PENDING:    state_str = "PAUSE_PENDING";    break;
                case SERVICE_CONTINUE_PENDING: state_str = "CONTINUE_PENDING"; break;
            }
            internal_printf("  [%-16s][%s] %s  (%s: %s)\n", state_str, cat_tag, info, tag, svc_name);
            stopped++;
        }
    }

    ADVAPI32$CloseServiceHandle(hScm);

    if (running == 0 && stopped == 0)
        internal_printf("  (status query denied for all detected products)\n");
}

void go(char *args, int len)
{
    bofstart();

    datap parser;
    BeaconDataParse(&parser, args, len);

    wchar_t *target_w = BeaconDataExtract(&parser, NULL);
    if (!target_w || MSVCRT$wcslen(target_w) == 0) {
        internal_printf("Usage: edr_remote \\\\<target> [domain\\user] [password]\n");
        printoutput(TRUE);
        bofstop();
        return;
    }

    wchar_t *cred_user = BeaconDataExtract(&parser, NULL);
    wchar_t *cred_pass = BeaconDataExtract(&parser, NULL);

    char target_mb[256];
    wc_to_mb(target_w, target_mb, sizeof(target_mb));

    internal_printf("=== EDR Remote Enum: %s ===\n", target_mb);

    BOOL session_added    = FALSE;
    BOOL impersonating    = FALSE;
    HANDLE hLogonToken    = NULL;

    if (cred_user && MSVCRT$wcslen(cred_user) > 0) {

        for (wchar_t *p = cred_user; *p; p++) {
            if (*p == L'/') *p = L'\\';
        }

        char user_mb[256];
        wc_to_mb(cred_user, user_mb, sizeof(user_mb));
        internal_printf("[*] Authenticating as %s...\n", user_mb);

        wchar_t domain_part[128] = {0};
        wchar_t user_part[128]   = {0};
        wchar_t *backslash = MSVCRT$wcschr(cred_user, L'\\');
        if (backslash) {
            int domain_len = (int)(backslash - cred_user);
            for (int k = 0; k < domain_len; k++)
                domain_part[k] = cred_user[k];
            domain_part[domain_len] = 0;
            MSVCRT$wcscpy(user_part, backslash + 1);
        } else {
            MSVCRT$wcscpy(user_part, cred_user);
        }

        NETRESOURCEW nr;
        MSVCRT$memset(&nr, 0, sizeof(nr));
        nr.dwType       = RESOURCETYPE_ANY;
        nr.lpRemoteName = target_w;

        DWORD ret = MPR$WNetAddConnection2W(
            &nr,
            cred_pass && MSVCRT$wcslen(cred_pass) > 0 ? cred_pass : NULL,
            cred_user,
            0);

        if (ret == 0 || ret == ERROR_SESSION_CREDENTIAL_CONFLICT) {
            internal_printf("[+] Session established\n");
            session_added = TRUE;
        } else {
            internal_printf("[-] WNetAddConnection2W failed: %lu — trying with current token\n", ret);
        }

        wchar_t *pass_w = (cred_pass && MSVCRT$wcslen(cred_pass) > 0) ? cred_pass : L"";
        BOOL logon_ok = ADVAPI32$LogonUserW(
            user_part,
            MSVCRT$wcslen(domain_part) > 0 ? domain_part : NULL,
            pass_w,
            LOGON32_LOGON_NEW_CREDENTIALS,  /* type 9 — network-style, no local logon */
            LOGON32_PROVIDER_DEFAULT,
            &hLogonToken);

        if (logon_ok && hLogonToken) {
            if (ADVAPI32$ImpersonateLoggedOnUser(hLogonToken)) {
                impersonating = TRUE;
            } else {
                internal_printf("[-] ImpersonateLoggedOnUser failed: %lu\n", KERNEL32$GetLastError());
            }
        } else {
            internal_printf("[-] LogonUserW failed: %lu — SCM will use current token\n", KERNEL32$GetLastError());
        }

    } else {
        internal_printf("[*] Using current beacon token\n");
    }

    int installed_edr = 0, installed_av = 0, installed_telemetry = 0, installed_epp = 0;

    /* Abrir LSA policy una vez para fases 1 y 3 */
    LSA_UNICODE_STRING sysname_go;
    sysname_go.Buffer        = (wchar_t*)target_w;
    sysname_go.Length        = (USHORT)(MSVCRT$wcslen(target_w) * sizeof(wchar_t));
    sysname_go.MaximumLength = sysname_go.Length + sizeof(wchar_t);

    LSA_OBJECT_ATTRIBUTES objAttr_go;
    MSVCRT$memset(&objAttr_go, 0, sizeof(objAttr_go));
    objAttr_go.Length = sizeof(LSA_OBJECT_ATTRIBUTES);

    LSA_HANDLE hPolicy_shared = NULL;
    NTSTATUS st_go = ADVAPI32$LsaOpenPolicy(
        &sysname_go, &objAttr_go,
        POLICY_LOOKUP_NAMES,
        &hPolicy_shared);

    if (st_go != 0) {
        internal_printf("[-] LsaOpenPolicy failed: 0x%08X\n", (unsigned)st_go);
    } else {
        phase_lsar_services(hPolicy_shared, &installed_edr, &installed_av, &installed_telemetry, &installed_epp);
        ADVAPI32$LsaClose(hPolicy_shared);
    }


    phase_scm_drivers(target_mb, &installed_edr, &installed_av, &installed_telemetry, &installed_epp);

    phase_scm_status(target_mb);

    internal_printf("\n====================================================\n");
    internal_printf("  Target: %s\n", target_mb);
    internal_printf("  [INSTALLED] = registered in SCM (may be stopped)\n");
    internal_printf("  [RUNNING  ] = confirmed active via QueryServiceStatusEx\n");
    internal_printf("  [STOPPED  ] = installed but not running\n");
    internal_printf("====================================================\n\n");

    if (impersonating) {
        ADVAPI32$RevertToSelf();
    }
    if (hLogonToken) {
        KERNEL32$CloseHandle(hLogonToken);
    }
    if (session_added) {
        MPR$WNetCancelConnection2W(target_w, 0, TRUE);
    }

    printoutput(TRUE);
    bofstop();
}
