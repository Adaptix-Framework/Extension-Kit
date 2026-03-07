var metadata = {
    name: "EDR-BOF",
    description: "EDR/AV/EPP enumeration BOF suite — local (services + drivers + processes) and remote (LsarLookupNames + SCM). 444 signatures, 48 vendors."
};


// Signature databases

var PROC_SIGS = {
    "a2guard.exe": "Emsisoft | Behavior Blocker | AV",
    "a2service.exe": "Emsisoft | Anti-Malware Service | AV",
    "a2start.exe": "Emsisoft | Anti-Malware UI | AV",
    "activeprobe.exe": "Cybereason | Active Probe | EDR",
    "alunotify.exe": "AhnLab | Update Notification | AV",
    "ampdaemon.exe": "Cisco | AMP Daemon | EDR",
    "asdsvc.exe": "AhnLab | ASD Service | AV",
    "avastsvc.exe": "Avast | Service | AV",
    "avastui.exe": "Avast | UI | AV",
    "avgnt.exe": "Avira | Desktop Notification | AV",
    "avgsvc.exe": "AVG | Service | AV",
    "avguard.exe": "Avira | Real-Time Protection | AV",
    "avgui.exe": "AVG | UI | AV",
    "avp.exe": "Kaspersky | Endpoint Security | AV",
    "avpexec.exe": "Kaspersky | AV Process Launcher | AV",
    "avpui.exe": "Kaspersky | Endpoint Security UI | AV",
    "avscan.exe": "Avira | Scanner | AV",
    "avshadow.exe": "Avira | Shadow Copy Service | AV",
    "bdagent.exe": "Bitdefender | Agent | AV",
    "bdredline.exe": "Bitdefender | Redline Agent | EDR",
    "bdservicehost.exe": "Bitdefender | Service Host | AV",
    "cavse.exe": "Comodo | AV Scanner Engine | AV",
    "cb.exe": "Carbon Black | App Control | EDR",
    "cbcomms.exe": "Carbon Black | Communications | EDR",
    "cbdefense.exe": "Carbon Black | Cloud Defense | EDR",
    "cbdefenseservice.exe": "Carbon Black | Defense Service | EDR",
    "cbstream.exe": "Carbon Black | Stream | EDR",
    "ccsvchst.exe": "Broadcom | Symantec Endpoint Protection | EPP",
    "cesvc.exe": "Xcitium | Endpoint Service | EPP",
    "cis.exe": "Comodo | Internet Security | EPP",
    "clientcommunicationservice.exe": "Trend Micro | Client Communication | EPP",
    "cmdagent.exe": "Comodo | Agent | EPP",
    "configsecuritypolicy.exe": "Microsoft | Defender Config Policy | AV",
    "coreserviceshell.exe": "Trend Micro | Apex One | EDR",
    "cpda.exe": "Check Point | Daemon Agent | EPP",
    "crssvc.exe": "Cybereason | Sensor Service | EDR",
    "csagent.exe": "CrowdStrike | Falcon Agent | EDR",
    "csfalconcontainer.exe": "CrowdStrike | Falcon | EDR",
    "csfalconservice.exe": "CrowdStrike | Falcon | EDR",
    "cylanceoptics.exe": "BlackBerry | Cylance OPTICS | EDR",
    "cylancesvc.exe": "BlackBerry | Cylance PROTECT | EPP",
    "cylanceui.exe": "BlackBerry | Cylance UI | EPP",
    "cyoptics.exe": "Palo Alto | Cortex XDR Optics | EDR",
    "cyserver.exe": "Palo Alto | Cortex XDR Server | EDR",
    "cytray.exe": "Palo Alto | Cortex XDR Tray | EDR",
    "cyveraservice.exe": "Palo Alto | Cortex XDR Cyvera | EDR",
    "deepinstinctagent.exe": "Deep Instinct | Agent | EDR",
    "ds_agent.exe": "Trend Micro | Deep Security Agent | EDR",
    "dwengine.exe": "Dr.Web | Scanning Engine | AV",
    "dwnetfilter.exe": "Dr.Web | Network Filter | AV",
    "dwscanner.exe": "Dr.Web | Scanner | AV",
    "dwservice.exe": "Dr.Web | Service | AV",
    "eamsi.exe": "ESET | AMSI Scanner | AV",
    "ecls.exe": "ESET | Command Line Scanner | AV",
    "eei_agent.exe": "ESET | Inspect Agent | EDR",
    "egui.exe": "ESET | GUI | AV",
    "ekrn.exe": "ESET | Kernel Service | AV",
    "elastic-agent.exe": "Elastic | Elastic Agent | EDR",
    "elastic-endpoint.exe": "Elastic | Elastic Endpoint | EDR",
    "endpointbasecamp.exe": "Trend Micro | Vision One Basecamp | EDR",
    "epag.exe": "Bitdefender | GravityZone Agent | EDR",
    "epfw.exe": "ESET | Personal Firewall | AV",
    "epintegrationservice.exe": "Bitdefender | Integration Service | EDR",
    "epmonitor.exe": "Check Point | Endpoint Monitor | EPP",
    "epmworker.exe": "Check Point | Endpoint Worker | EPP",
    "epp.exe": "Malwarebytes | Endpoint Protection | EPP",
    "epprotectedservice.exe": "Bitdefender | Protected Service | EDR",
    "epsecurityservice.exe": "Bitdefender | Endpoint Security | EDR",
    "essvc.exe": "ESET | Security Service | AV",
    "executionpreventionsvc.exe": "Cybereason | Execution Prevention | EDR",
    "falconhost.exe": "CrowdStrike | Falcon Host | EDR",
    "filebeat.exe": "Elastic | Filebeat | Telemetry",
    "firesvc.exe": "Trellix | FireEye HX Agent | EDR",
    "firetray.exe": "Trellix | FireEye HX Tray | EDR",
    "fortiagent.exe": "Fortinet | FortiClient Agent | EPP",
    "fortiavmon.exe": "Fortinet | FortiClient AV Monitor | AV",
    "forticollector.exe": "Fortinet | FortiEDR Collector | EDR",
    "fortiedr.exe": "Fortinet | FortiEDR Collector | EDR",
    "fortitray.exe": "Fortinet | FortiClient Tray | EPP",
    "fortiwf.exe": "Fortinet | FortiClient Web Filter | EPP",
    "fsav32.exe": "WithSecure | F-Secure AV | AV",
    "fsgk32.exe": "WithSecure | F-Secure GateKeeper | AV",
    "gdfsvc.exe": "G Data | File Server Security | AV",
    "gdsc.exe": "G Data | Security Client | AV",
    "gdscan.exe": "G Data | AV Scanner | AV",
    "hmpalert.exe": "Sophos | Intercept X | EDR",
    "huntressagent.exe": "Huntress | Agent | EDR",
    "huntressupdater.exe": "Huntress | Updater | EDR",
    "hurukai.exe": "HarfangLab | EDR Agent | EDR",
    "iptray.exe": "Cisco | Secure Endpoint Tray | EDR",
    "ir_agent.exe": "Rapid7 | Insight Agent | EDR",
    "kavfs.exe": "Kaspersky | File Server Security | AV",
    "klnagent.exe": "Kaspersky | Network Agent | EPP",
    "klnsacwsvc.exe": "Kaspersky | Network Security Agent | EPP",
    "logcollector.exe": "SentinelOne | Log Collector | EDR",
    "macmnsvc.exe": "Trellix | McAfee Agent | EPP",
    "masvc.exe": "Trellix | McAfee Agent Service | EPP",
    "mbam.exe": "Malwarebytes | Anti-Malware | AV",
    "mbamagent.exe": "Malwarebytes | Agent | AV",
    "mbamservice.exe": "Malwarebytes | Anti-Malware Service | AV",
    "mbamtray.exe": "Malwarebytes | System Tray | AV",
    "mcshield.exe": "Trellix | McAfee On-Access Scanner | AV",
    "mctray.exe": "Trellix | McAfee Tray | EPP",
    "mediapatcher.exe": "Check Point | Media Encryption | EPP",
    "metricbeat.exe": "Elastic | Metricbeat | Telemetry",
    "mfeatp.exe": "Trellix | McAfee ATP | EDR",
    "mfecanary.exe": "Trellix | McAfee Canary Process | EPP",
    "mfeesp.exe": "Trellix | McAfee Endpoint Security | EPP",
    "mfemactl.exe": "Trellix | McAfee Agent Control | EPP",
    "mfemms.exe": "Trellix | McAfee Management Service | EPP",
    "mfetp.exe": "Trellix | McAfee Threat Prevention | EPP",
    "minionhost.exe": "Cybereason | Minion Host | EDR",
    "mpdefendercoreservice.exe": "Microsoft | Defender Core Service | AV",
    "msmpeng.exe": "Microsoft | Defender Antimalware | AV",
    "msseces.exe": "Microsoft | Security Essentials | AV",
    "mssense.exe": "Microsoft | Defender for Endpoint | EDR",
    "navapsvc.exe": "Norton | AntiVirus Auto-Protect | AV",
    "nissrv.exe": "Microsoft | Defender NIS | AV",
    "nortonsecurity.exe": "Norton | Security UI | AV",
    "ns.exe": "Norton | Security Service | AV",
    "nsservice.exe": "Norton | Security Service | AV",
    "nswocsvc.exe": "Norton | WSC Service | AV",
    "ntrtscan.exe": "Trend Micro | Real-time Scan | AV",
    "orbital.exe": "Cisco | Orbital Agent | EDR",
    "ossec-agent.exe": "Wazuh | OSSEC Agent | SIEM-EDR",
    "overseer.exe": "Avast | Overseer | AV",
    "pccntmon.exe": "Trend Micro | PC-cillin Monitor | AV",
    "personalfirewallservice.exe": "Trend Micro | Personal Firewall | EPP",
    "psanhost.exe": "WatchGuard | Panda Endpoint | EPP",
    "psuaservice.exe": "WatchGuard | Panda Endpoint Service | EPP",
    "pyminionhost.exe": "Cybereason | Python Minion Host | EDR",
    "qualysagent.exe": "Qualys | Cloud Agent | Vuln Scanner",
    "repserv.exe": "Carbon Black | Server | EDR",
    "repux.exe": "Carbon Black | Response | EDR",
    "repwsc.exe": "Carbon Black | Watchdog | EDR",
    "rphcp.exe": "LimaCharlie | Sensor | EDR",
    "rtvscan.exe": "Broadcom | Symantec Real-Time Scan | AV",
    "savservice.exe": "Sophos | SAV Service | AV",
    "sbamsvc.exe": "VIPRE | Anti-Malware Service | AV",
    "sbamuisrv.exe": "VIPRE | UI Service | AV",
    "securityhealthservice.exe": "Microsoft | Security Health | AV",
    "securityhealthsystray.exe": "Microsoft | Security Health Tray | AV",
    "sense.exe": "Microsoft | Defender for Endpoint Sense | EDR",
    "sensecncproxy.exe": "Microsoft | Defender for Endpoint | EDR",
    "sentinelagent.exe": "SentinelOne | Singularity Agent | EDR",
    "sentinelhelper.exe": "SentinelOne | Helper | EDR",
    "sentinelmemoryscanner.exe": "SentinelOne | Memory Scanner | EDR",
    "sentinelone.exe": "SentinelOne | Singularity | EDR",
    "sentinelservicehost.exe": "SentinelOne | Service Host | EDR",
    "sentinelstaticengine.exe": "SentinelOne | Static Engine | EDR",
    "sentinelstaticenginescanner.exe": "SentinelOne | Static Engine Scanner | EDR",
    "sentineluiagent.exe": "SentinelOne | UI Agent | EDR",
    "sepmasterservice.exe": "Broadcom | SEP Master Service | EPP",
    "sepwscsvc64.exe": "Broadcom | SEP WSC Service | EPP",
    "sgrmbroker.exe": "Microsoft | System Guard Runtime Broker | AV",
    "smc.exe": "Broadcom | Symantec Management Client | EPP",
    "smcgui.exe": "Broadcom | Symantec Management Client | EPP",
    "snac.exe": "Broadcom | Symantec Network Access Control | EPP",
    "sophosagent.exe": "Sophos | Management Agent | EPP",
    "sophoscleanm.exe": "Sophos | Clean Manager | EPP",
    "sophosfilescanner.exe": "Sophos | File Scanner | AV",
    "sophosfs.exe": "Sophos | File Scanner | AV",
    "sophoshealth.exe": "Sophos | Health Service | EPP",
    "sophosinterceptx.exe": "Sophos | Intercept X | EDR",
    "sophosntp.exe": "Sophos | Network Threat Protection | EPP",
    "sophossps.exe": "Sophos | Sophos Endpoint | EPP",
    "sophosui.exe": "Sophos | Sophos UI | EPP",
    "spideragent.exe": "Dr.Web | SpIDer Agent | AV",
    "splunkd.exe": "Splunk | Universal Forwarder | Telemetry",
    "sspd.exe": "Sophos | Sophos Endpoint | EPP",
    "ssptray.exe": "Sophos | Tray App | EPP",
    "sysmon.exe": "Microsoft | Sysmon | Telemetry",
    "sysmon64.exe": "Microsoft | Sysmon 64-bit | Telemetry",
    "taniumclient.exe": "Tanium | Client | EPP",
    "taniumdetect.exe": "Tanium | Detect | EDR",
    "taniumendpointindex.exe": "Tanium | Endpoint Index | EDR",
    "tmbmsrv.exe": "Trend Micro | Unauthorized Change Prevention | EPP",
    "tmccsf.exe": "Trend Micro | Common Client Framework | EPP",
    "tmlisten.exe": "Trend Micro | Listener | EPP",
    "tmntsrv.exe": "Trend Micro | Ntrtscan | AV",
    "tmproxy.exe": "Trend Micro | Web Reputation Proxy | EPP",
    "traborchestrator.exe": "Palo Alto | Cortex XDR Traps | EDR",
    "tracsvrcalc.exe": "Check Point | Tracker Service | EPP",
    "trapsagent.exe": "Palo Alto | Traps Agent | EDR",
    "trapsd.exe": "Palo Alto | Cortex XDR Traps Daemon | EDR",
    "v3sp.exe": "AhnLab | V3 Service Platform | AV",
    "v3svc.exe": "AhnLab | V3 Endpoint Service | AV",
    "velociraptor.exe": "Velociraptor | Agent | DFIR",
    "wazuh-agent.exe": "Wazuh | Agent | SIEM-EDR",
    "winlogbeat.exe": "Elastic | Winlogbeat | Telemetry",
    "wrsa.exe": "Webroot | SecureAnywhere | AV",
    "wsc_proxy.exe": "Avast | WSC Proxy | AV",
    "wscservice.exe": "Trend Micro | Web Security Client | EPP",
    "xagt.exe": "Trellix | FireEye HX Agent | EDR",
    "zsaservice.exe": "Zscaler | Client Connector Service | ZTNA",
    "zsatray.exe": "Zscaler | Client Connector Tray | ZTNA",
    "zsatraymanager.exe": "Zscaler | Tray Manager | ZTNA",
    "zstunnel.exe": "Zscaler | Tunnel Service | ZTNA",
};

var SVC_SIGS = {
    "a2guard": "Emsisoft | Behavior Blocker | AV",
    "a2service": "Emsisoft | Anti-Malware Service | AV",
    "activeprobe": "Cybereason | Active Probe | EDR",
    "antivirscheduler": "Avira | Scheduler Service | AV",
    "antivirservice": "Avira | AntiVir Service | AV",
    "asdsvc": "AhnLab | ASD Service | AV",
    "avast": "Avast | Antivirus | AV",
    "avastsvc": "Avast | AV Service | AV",
    "avgantivirus": "AVG | Antivirus Service | AV",
    "avgsvc": "AVG | AV Service | AV",
    "avguard": "Avira | Real-Time Protection | AV",
    "avp": "Kaspersky | Endpoint Security | AV",
    "bdredline": "Bitdefender | Redline Agent | EDR",
    "carbonblack": "Carbon Black | EDR | EDR",
    "cbcomms": "Carbon Black | Comms | EDR",
    "cbdefense": "Carbon Black | Cloud Defense | EDR",
    "cbstream": "Carbon Black | Streaming | EDR",
    "ccsvchst": "Broadcom | Symantec Endpoint Protection | EPP",
    "ciscoampsvc": "Cisco | Secure Endpoint Service | EDR",
    "cmdagent": "Comodo | Agent Service | EPP",
    "coreserviceshell": "Trend Micro | Apex One | EDR",
    "crssvc": "Cybereason | Sensor | EDR",
    "csagent": "CrowdStrike | Falcon Agent | EDR",
    "csfalconcontainer": "CrowdStrike | Falcon Container | EDR",
    "csfalconservice": "CrowdStrike | Falcon Sensor | EDR",
    "cylancesvc": "BlackBerry | Cylance PROTECT | EPP",
    "cyserver": "Palo Alto | Cortex XDR Server | EDR",
    "cyverasvc": "Palo Alto | Cortex XDR Cyvera | EDR",
    "deepinstinctsvc": "Deep Instinct | Agent | EDR",
    "drwebservice": "Dr.Web | Service | AV",
    "ds_agent": "Trend Micro | Deep Security | EDR",
    "dwengine": "Dr.Web | Scanning Engine | AV",
    "eei_agent": "ESET | Inspect Agent | EDR",
    "ekrn": "ESET | Kernel Service | AV",
    "elastic-agent": "Elastic | Elastic Agent | EDR",
    "elastic-endpoint": "Elastic | Elastic Endpoint | EDR",
    "epag": "Bitdefender | GravityZone | EDR",
    "epintegrationservice": "Bitdefender | Integration Service | EDR",
    "epprotectedservice": "Bitdefender | Protected Service | EDR",
    "epsecurity": "Check Point | Endpoint Security | EPP",
    "epsecurityservice": "Bitdefender | Endpoint Security | EDR",
    "essvc": "ESET | Security Service | AV",
    "filebeat": "Elastic | Filebeat | Telemetry",
    "firesvc": "Trellix | FireEye HX Agent | EDR",
    "forticlientmon": "Fortinet | FortiClient Monitor | EPP",
    "forticollector": "Fortinet | FortiEDR Collector | EDR",
    "fortiedr": "Fortinet | FortiEDR | EDR",
    "fsav32": "WithSecure | F-Secure AV | AV",
    "fsgk32": "WithSecure | F-Secure GateKeeper | AV",
    "gdfsvc": "G Data | File Server Security | AV",
    "gdsc": "G Data | Security Client | AV",
    "gdscan": "G Data | Scanner | AV",
    "hmpalert": "Sophos | Intercept X | EDR",
    "huntressagent": "Huntress | Agent | EDR",
    "hurukai": "HarfangLab | EDR Agent | EDR",
    "immunetprotect": "Cisco | Immunet Protect | EDR",
    "ir_agent": "Rapid7 | Insight Agent | EDR",
    "klnagent": "Kaspersky | Network Agent | EPP",
    "macmnsvc": "Trellix | McAfee Agent | EPP",
    "masvc": "Trellix | McAfee Agent | EPP",
    "mbamservice": "Malwarebytes | Service | AV",
    "mdcoresvc": "Microsoft | Defender Core | AV",
    "mediapatcher": "Check Point | Media Encryption | EPP",
    "mfeesp": "Trellix | McAfee Endpoint Security | EPP",
    "mfefire": "Trellix | McAfee Firewall | EPP",
    "mfemms": "Trellix | McAfee Management | EPP",
    "mfetp": "Trellix | McAfee Threat Prevention | EPP",
    "mpssvc": "Microsoft | Defender Firewall | AV",
    "navapsvc": "Norton | Auto-Protect | AV",
    "norton": "Norton | Security Service | AV",
    "nsservice": "Norton | Security Service | AV",
    "nswocsvc": "Norton | WSC Service | AV",
    "orbital": "Cisco | Orbital Agent | EDR",
    "ossecagent": "Wazuh | OSSEC Agent | SIEM-EDR",
    "psanhost": "WatchGuard | Panda Endpoint | EPP",
    "psuaservice": "WatchGuard | Panda Endpoint Service | EPP",
    "qualysagent": "Qualys | Cloud Agent | Vuln Scanner",
    "rphcpsvc": "LimaCharlie | Sensor | EDR",
    "savservice": "Sophos | SAV Service | AV",
    "sbamsvc": "VIPRE | Anti-Malware Service | AV",
    "securityhealthservice": "Microsoft | Security Health | AV",
    "sense": "Microsoft | Defender for Endpoint | EDR",
    "sentinelagent": "SentinelOne | Singularity Agent | EDR",
    "sentinelstaticengine": "SentinelOne | Static Engine | EDR",
    "sepmasterservice": "Broadcom | SEP Master Service | EPP",
    "sepwscsvc": "Broadcom | SEP WSC Service | EPP",
    "sophosagent": "Sophos | Management Agent | EPP",
    "sophosfilescanner": "Sophos | File Scanner | AV",
    "sophoshealth": "Sophos | Health Service | EPP",
    "sophosntpservice": "Sophos | Network Threat Protection | EPP",
    "sophossps": "Sophos | Endpoint | EPP",
    "spideragent": "Dr.Web | SpIDer Agent | AV",
    "splunkforwarder": "Splunk | Forwarder | Telemetry",
    "sysmon": "Microsoft | Sysmon | Telemetry",
    "sysmon64": "Microsoft | Sysmon 64 | Telemetry",
    "taniumclient": "Tanium | Client | EPP",
    "taniumdetect": "Tanium | Detect | EDR",
    "tmbmsrv": "Trend Micro | Unauthorized Change Prevention | EPP",
    "tmlisten": "Trend Micro | Listener | EPP",
    "tmntsrv": "Trend Micro | OfficeScan NT | AV",
    "tracsvrcalc": "Check Point | Tracker Service | EPP",
    "trapssvc": "Palo Alto | Traps Service | EDR",
    "v3svc": "AhnLab | V3 Endpoint | AV",
    "velociraptor": "Velociraptor | Agent | DFIR",
    "wazuhsvc": "Wazuh | Agent | SIEM-EDR",
    "wdnissvc": "Microsoft | Defender Network Inspection | AV",
    "webthreatdefsvc": "Microsoft | Web Threat Defense | AV",
    "webthreatdefusersvc": "Microsoft | Web Threat Defense (User) | AV",
    "windefend": "Microsoft | Windows Defender AV | AV",
    "winlogbeat": "Elastic | Winlogbeat | Telemetry",
    "wrsa": "Webroot | SecureAnywhere | AV",
    "wscsvc": "Microsoft | Security Center | AV",
    "xagt": "Trellix | FireEye HX | EDR",
    "zscalerservice": "Zscaler | Client Connector | ZTNA",
    "ztunnel": "Zscaler | Tunnel Service | ZTNA",
};

var DRV_SIGS = {
    "a2accx64": "Emsisoft | Access Filter (x64) | AV",
    "a2dskm": "Emsisoft | Disk Monitor Driver | AV",
    "ahksvr": "AhnLab | Hook Server Driver | AV",
    "aswarpt": "Avast | Anti-Rootkit Driver | AV",
    "aswbidsdriver": "Avast | Behavior Shield Driver | AV",
    "aswbidsha": "Avast | Behavior Shield A | AV",
    "aswelam": "Avast | ELAM Driver | AV",
    "aswmonflt": "Avast | Monitor Minifilter | AV",
    "aswsnx": "Avast | Virtualization Driver | AV",
    "aswsp": "Avast | Self-Protection Driver | AV",
    "aswstm": "Avast | Stream Filter | AV",
    "avckf": "Bitdefender | AV Callback Filter | AV",
    "avgntflt": "Avira | Network Filter Driver | AV",
    "avipbb": "Avira | IP Blocker Bridge | AV",
    "avkmgr": "Avira | AV Kernel Manager | AV",
    "bddevflt": "Bitdefender | Device Filter | AV",
    "bdelam": "Bitdefender | ELAM Driver | AV",
    "bdfndisf": "Bitdefender | Network Filter | AV",
    "bdfwfpf": "Bitdefender | WFP Firewall Filter | AV",
    "bdselfpr": "Bitdefender | Self-Protection Driver | EDR",
    "bhdrvx64": "Broadcom | Symantec SONAR Driver | EPP",
    "carbonblackk": "Carbon Black | Kernel Driver | EDR",
    "cbk7": "Carbon Black | Kernel Module | EDR",
    "cmdguard": "Comodo | Guard Driver | EPP",
    "cmdhlp": "Comodo | Helper Driver | EPP",
    "cpprotect": "Check Point | SandBlast Protection Driver | EDR",
    "csagent": "CrowdStrike | Falcon Kernel Driver | EDR",
    "csboot": "CrowdStrike | Falcon Boot Driver | EDR",
    "csdevicecontrol": "CrowdStrike | Device Control Driver | EDR",
    "cticomms": "Carbon Black | Comms Driver | EDR",
    "ctifile": "Carbon Black | File Filter | EDR",
    "cybkerneltracker": "CyberArk | Kernel Tracker Driver | EPP",
    "cylancedrv": "BlackBerry | Cylance Kernel Driver | EPP",
    "cyverak": "Palo Alto | Cortex XDR Kernel Driver | EDR",
    "cyvrfsfd": "Palo Alto | Cortex XDR FS Filter | EDR",
    "deepinstinctdrv": "Deep Instinct | Kernel Driver | EDR",
    "dwprot": "Dr.Web | Protection Driver | AV",
    "eamonm": "ESET | File System Monitor | AV",
    "edevmon": "ESET | Device Monitor | AV",
    "eelam": "ESET | ELAM Driver | AV",
    "ehdrv": "ESET | Helper Driver | AV",
    "ekbdflt": "ESET | Keyboard Filter | AV",
    "elasticendpoint": "Elastic | Endpoint Driver | EDR",
    "epfw": "ESET | Firewall Driver | AV",
    "epfwwfp": "ESET | Firewall WFP Driver | AV",
    "epklib": "Check Point | Endpoint Kernel Library | EPP",
    "esensor": "Endgame | Sensor Driver | EDR",
    "farflt": "Malwarebytes | File System Monitor | AV",
    "fdedrdrv": "Fortinet | FortiEDR Kernel Driver | EDR",
    "fekern": "Trellix | FireEye Kernel Driver | EDR",
    "fortimon": "Fortinet | FortiClient Monitor Driver | EPP",
    "fortishield": "Fortinet | FortiEDR Shield Driver | EDR",
    "fsatp": "WithSecure | F-Secure ATP Driver | EDR",
    "fsdfw": "WithSecure | F-Secure Firewall Driver | AV",
    "fses": "WithSecure | F-Secure Endpoint Driver | AV",
    "fshs": "WithSecure | F-Secure HS Driver | AV",
    "gddisk": "G Data | Disk Filter | AV",
    "gdkbflt64": "G Data | Kernel Block Filter | AV",
    "groundling64": "Secureworks | Red Cloak Driver (x64) | EDR",
    "gzflt": "Bitdefender | GravityZone Minifilter | EDR",
    "hmpalert": "Sophos | HitmanPro.Alert Driver | EDR",
    "huntressdrv": "Huntress | Kernel Driver | EDR",
    "hxdriver": "Trellix | FireEye HX Kernel Driver | EDR",
    "immunetprotect": "Cisco | Secure Endpoint Protection | EDR",
    "immunetselfprotect": "Cisco | Secure Endpoint Self-Protection | EDR",
    "inspect": "Comodo | File Inspection Driver | EPP",
    "isedrv": "Cisco | ISE Posture Driver | EPP",
    "klam": "Kaspersky | Anti-Malware Filter | AV",
    "klbackupdisk": "Kaspersky | Backup Disk Filter | AV",
    "klboot": "Kaspersky | Boot Driver | AV",
    "kldisk": "Kaspersky | Disk Filter | AV",
    "klelam": "Kaspersky | ELAM Driver | AV",
    "klhk": "Kaspersky | Hook Driver | AV",
    "klif": "Kaspersky | Interceptor Filter | AV",
    "kltdi": "Kaspersky | TDI Driver | AV",
    "klwfp": "Kaspersky | WFP Callout Driver | AV",
    "kneps": "Kaspersky | Network Protection | AV",
    "mbam": "Malwarebytes | Anti-Malware Driver | AV",
    "mbamswissarmy": "Malwarebytes | Swiss Army Kernel Driver | AV",
    "mfeaskm": "Trellix | McAfee Anti-Stealth Kernel | EPP",
    "mfeavfk": "Trellix | McAfee AV Filter Kernel | AV",
    "mfefirek": "Trellix | McAfee Firewall Kernel | EPP",
    "mfehidk": "Trellix | McAfee HIPS IDS Kernel | EPP",
    "mfencbdc": "Trellix | McAfee Network Control | EPP",
    "mfencfilter": "Trellix | McAfee Network Content Filter | EPP",
    "mfewfpk": "Trellix | McAfee WFP Kernel | EPP",
    "mssecflt": "Microsoft | Defender for Endpoint Minifilter | EDR",
    "naveng": "Norton | NAV Engine | AV",
    "navex": "Norton | NAV Extraction | AV",
    "nxtrdrv": "Nexthink | Endpoint Driver | Telemetry",
    "psinfile": "WatchGuard | Panda File Filter | EPP",
    "psinproc": "WatchGuard | Panda Process Filter | EPP",
    "pskmad": "WatchGuard | Panda Kernel Monitor | EPP",
    "psycheddriver": "Cybereason | Kernel Driver | EDR",
    "psychedfilterdriver": "Cybereason | Minifilter Driver | EDR",
    "safestorefilter": "Sophos | SafeStore Filter | EPP",
    "savonaccess": "Sophos | On-Access Filter | AV",
    "sbredrv": "VIPRE | Kernel Driver | AV",
    "sdcfilter": "Sophos | Data Control Filter | EPP",
    "sentineldevicecontrol": "SentinelOne | Device Control Driver | EDR",
    "sentinelelam": "SentinelOne | ELAM Driver | EDR",
    "sentinelmonitor": "SentinelOne | Kernel Monitor | EDR",
    "sentinelnetworkmonitor": "SentinelOne | Network Monitor Driver | EDR",
    "sophosed": "Sophos | Endpoint Defense Driver | EPP",
    "sophosntpflt": "Sophos | NTP Minifilter | EPP",
    "srtsp": "Broadcom | Symantec Real-Time SP | AV",
    "srtspx": "Broadcom | SEP Real-Time SP | AV",
    "symds": "Norton | Symantec DS Driver | AV",
    "symefa": "Broadcom | Symantec Extended File Attrs | EPP",
    "symefasi": "Broadcom | Symantec FS Monitor | EPP",
    "symevent": "Broadcom | Symantec Event Driver | EPP",
    "symnets": "Norton | Symantec Network Security | AV",
    "sysmondrv": "Microsoft | Sysmon Driver | Telemetry",
    "taniumrecorderdrv": "Tanium | Recorder Kernel Driver | Telemetry",
    "tladriver": "Palo Alto | Cortex XDR TLA Driver | EDR",
    "tmactmon": "Trend Micro | Activity Monitor Driver | EDR",
    "tmcomm": "Trend Micro | Common Module Driver | EPP",
    "tmebc": "Trend Micro | Exploit Block Driver | EDR",
    "tmevtmgr": "Trend Micro | Event Manager Driver | EDR",
    "tmtdi": "Trend Micro | TDI Driver | EPP",
    "tmumh": "Trend Micro | UMH Driver | EPP",
    "tmxpflt": "Trend Micro | Cross-Platform Minifilter | EDR",
    "trufos": "Bitdefender | Scanning Driver | AV",
    "v3flt2k": "AhnLab | V3 Filter Driver | AV",
    "v3monitor": "AhnLab | V3 Endpoint Monitor | AV",
    "wdboot": "Microsoft | Defender Boot Driver | AV",
    "wdfilter": "Microsoft | Defender Minifilter | AV",
    "wdnisdrv": "Microsoft | Defender NIS Driver | AV",
    "wfp_mrt": "Trellix | FireEye WFP MRT Driver | EDR",
    "wrkrn": "Webroot | Kernel Driver | AV",
    "xfsgk": "WithSecure | F-Secure GateKeeper Driver | AV",
    "zscalertun": "Zscaler | Tunnel Driver | ZTNA",
};

function normalize(s) {
    return s.trim().toLowerCase().replace(/[-_\s]+/g, "");
}

var _normCache = {};
function getNormDb(db, tag) {
    if (_normCache[tag]) return _normCache[tag];
    var nd = {};
    for (var k in db) {
        if (db.hasOwnProperty(k)) nd[normalize(k)] = db[k];
    }
    _normCache[tag] = nd;
    return nd;
}

function matchSigs(names, db, tag) {
    var ndb = getNormDb(db, tag);
    var hits = [];
    for (var i = 0; i < names.length; i++) {
        var n = normalize(names[i]);
        if (ndb.hasOwnProperty(n)) {
            var parts = ndb[n].split("|");
            hits.push({
                name:    names[i].trim(),
                vendor:  parts[0] ? parts[0].trim() : "?",
                product: parts[1] ? parts[1].trim() : names[i],
                cat:     parts[2] ? parts[2].trim() : "OTH"
            });
        }
    }
    return hits;
}

function threatLevel(hits) {
    var cats = {};
    for (var i = 0; i < hits.length; i++) cats[hits[i].cat] = true;
    if (cats["EDR"])                                   return "[!] THREAT LEVEL: HIGH     - EDR detected (kernel callbacks/hooks likely active)";
    if (cats["AV"] && (cats["EPP"] || hits.length > 1)) return "[~] THREAT LEVEL: MODERATE - AV + Telemetry";
    if (cats["AV"])                                    return "[~] THREAT LEVEL: LOW-MOD  - AV only";
    if (cats["EPP"])                                   return "[-] THREAT LEVEL: LOW      - EPP / non-EDR";
    if (hits.length === 0)                             return "[?] THREAT LEVEL: UNKNOWN  - no matches";
    return "[-] THREAT LEVEL: LOW";
}

function formatResults(svcHits, drvHits, nSvcs, nDrvs) {
    var all = svcHits.concat(drvHits);
    var out = "\n====================================================\n";
    out += "  " + threatLevel(all) + "\n";
    out += "====================================================\n";
    if (svcHits.length > 0) {
        out += "\nServices matched (" + svcHits.length + "):\n";
        for (var i = 0; i < svcHits.length; i++) {
            var h = svcHits[i];
            out += "  [" + h.cat + "] " + h.vendor + " - " + h.product + "  (" + h.name + ")\n";
        }
    }
    if (drvHits.length > 0) {
        out += "\nDrivers matched (" + drvHits.length + "):\n";
        for (var i = 0; i < drvHits.length; i++) {
            var h = drvHits[i];
            out += "  [" + h.cat + "] " + h.vendor + " - " + h.product + "  (" + h.name + ")\n";
        }
    }
    if (all.length === 0) out += "\n  No signatures matched.\n";
    out += "\n" + nSvcs + " services + " + nDrvs + " drivers enumerated  |  ";
    out += svcHits.length + " svc + " + drvHits.length + " drv hits\n";
    return out;
}

function parseBofOutput(text) {
    var svcs = [], drvs = [];
    var lines = text.split("\n");
    for (var i = 0; i < lines.length; i++) {
        var l = lines[i].trim();
        if (l.indexOf("SERVICE_NAME:") === 0)
            svcs.push(l.substring("SERVICE_NAME:".length).trim());
        else if (l.indexOf("DRIVER_NAME:") === 0)
            drvs.push(l.substring("DRIVER_NAME:".length).trim());
    }
    return { svcs: svcs, drvs: drvs };
}


// LOCAL BOF commands
var cmd_edr_both = ax.create_command("edr_both",
    "Local EDR enum: services + drivers [NOISE: low]",
    "edr_both");
cmd_edr_both.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path   = ax.script_dir() + "_bin/edrenum." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("short", [0]);
    var fired = false;
    let hook = function (task) {
        if (fired) return task;
        var p = parseBofOutput(task.text);
        if (p.svcs.length === 0 && p.drvs.length === 0) return task;
        fired = true;
        task.text += formatResults(matchSigs(p.svcs, SVC_SIGS, "svc"), matchSigs(p.drvs, DRV_SIGS, "drv"), p.svcs.length, p.drvs.length);
        return task;
    };
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: EDR enum (services + drivers)", hook);
});

var cmd_edr_svc = ax.create_command("edr_svc",
    "Local EDR enum: Win32 services only [NOISE: low]",
    "edr_svc");
cmd_edr_svc.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path   = ax.script_dir() + "_bin/edrenum." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("short", [1]);
    var fired = false;
    let hook = function (task) {
        if (fired) return task;
        var p = parseBofOutput(task.text);
        if (p.svcs.length === 0) return task;
        fired = true;
        task.text += formatResults(matchSigs(p.svcs, SVC_SIGS, "svc"), [], p.svcs.length, 0);
        return task;
    };
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: EDR enum (services only)", hook);
});

var cmd_edr_drv = ax.create_command("edr_drv",
    "Local EDR enum: kernel drivers only [NOISE: low]",
    "edr_drv");
cmd_edr_drv.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path   = ax.script_dir() + "_bin/edrenum." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("short", [2]);
    var fired = false;
    let hook = function (task) {
        if (fired) return task;
        var p = parseBofOutput(task.text);
        if (p.drvs.length === 0) return task;
        fired = true;
        task.text += formatResults([], matchSigs(p.drvs, DRV_SIGS, "drv"), 0, p.drvs.length);
        return task;
    };
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: EDR enum (drivers only)", hook);
});

// REMOTE BOF command

var cmd_edr_remote = ax.create_command("edr_remote",
    "Remote EDR enum via LsarLookupNames + SCM (services + kernel drivers) [NOISE: low-medium]",
    "edr_remote 192.168.1.10\nedr_remote 192.168.1.10 -u DOMAIN\\\\user -p password");

cmd_edr_remote.addArgString("target", true, "Target IP or hostname (e.g. 192.168.1.10)");
cmd_edr_remote.addArgFlagString("-u", "user", "DOMAIN\\user for explicit authentication (optional)", "");
cmd_edr_remote.addArgFlagString("-p", "pass", "Password for explicit authentication (optional)", "");

cmd_edr_remote.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var target = parsed_json["target"] || "";
    var user   = parsed_json["user"]   || "";
    var pass   = parsed_json["pass"]   || "";

    var unc_target = target.startsWith("\\\\") ? target : "\\\\" + target;

    let bof_path   = ax.script_dir() + "_bin/edrenumremote." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("wstr,wstr,wstr", [unc_target, user, pass]);
    let message    = "Task: Remote EDR enum on " + target;

    ax.execute_alias(id, cmdline, `execute bof -a ${bof_path} ${bof_params}`, message, null);
});

var group_edr = ax.create_commands_group("EDR-BOF", [
    cmd_edr_both,
    cmd_edr_svc,
    cmd_edr_drv,
    cmd_edr_remote
]);
ax.register_commands_group(group_edr, ["beacon", "gopher", "kharon"], ["windows"], []);
