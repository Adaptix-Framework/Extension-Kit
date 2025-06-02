# Process-BOF

This extension increases situational awareness of processes, modules, and services by providing a set of Beacon Object File (BOF) commands.

![](_img/01.png)

## findobj

Enumerate processes for specific modules or process handles. Taken from [outflanknl/C2-Tool-Collection](https://github.com/outflanknl/C2-Tool-Collection/tree/main/BOF/FindObjects)

```
findobj <type> <name>
```

| Type         | Description                                                  |
|--------------| ------------------------------------------------------------ |
| `module`     | Enumerate processes for specific loaded modules (eg. `winhttp.dll`, `amsi.dll` or  `clr.dll`). |
| `prochandle` | Enumerate processes for specific process handles (eg. `lsass.exe`). |

![](_img/02.png)



## process

Show detailed information from processes with established TCP and RDP connections.

```
process conn
```


## Credits
* C2-Tool-Collection - https://github.com/outflanknl/C2-Tool-Collection
