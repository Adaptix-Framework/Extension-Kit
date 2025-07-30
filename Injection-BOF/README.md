# Injection-BOF

Beacon Object Files for injects desired shellcode into target process

![](_img/01.png)

The **Inject** item will be added to the context menu in the Process Browser.

![](_img/02.png)

![](_img/03.png)



## inject-cfg

A beacon object file implementation of the process injection proof-of-concept from my blog post [Control Flow Hijacking via Data Pointers](https://www.legacyy.xyz/defenseevasion/windows/2025/04/16/control-flow-hijacking-via-data-pointers.html). Hijacks control flow via overwriting `combase.dll`'s Control Flow Guard function pointers called by COM proxying functions.
- From my testing, `explorer.exe` is the current best candidate in terms of an easy triggering mechanism due to its heavy reliance on COM proxying. Would recommend experimenting.
- **Make sure** shellcode is 64-bit as this BOF only supports 64-bit beacons & target processes.
- This has only been tested on windows versions `Win10 21H2 (19044.5737)` & `Win11 24H2 (26100.3775)`.

```
inject-cfg <pid> <shellcode file>
```



## inject-sec

Injects desired shellcode into target process using section mapping
```
inject-sec <pid> <shellcode file>
```



## inject-poolparty

Injects desired shellcode into target process using pool party
```
inject-poolparty <pid> <shellcode file> <technique id>
```



## Credits
* secinject - https://github.com/apokryptein/secinject
* DataInject-BOF - https://github.com/iilegacyyii/DataInject-BOF
* PoolParty - https://github.com/SafeBreach-Labs/PoolParty
