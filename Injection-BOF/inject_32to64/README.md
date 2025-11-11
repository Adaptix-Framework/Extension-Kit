## inject-32to64


This BOF implements WOW64 to native x64 process injection. It allows a 32-bit (WOW64) process to inject x64 shellcode into a native 64-bit process by performing a context switch to 64-bit mode.


- Injects x64 shellcode from a WOW64 process into a native 64-bit process
- Performs context switching from 32-bit to 64-bit mode and back
- Uses `RtlCreateUserThread` to create a remote thread in the target process

## Usage

```
inject-32to64 <pid> <shellcode_file>
```

- `pid` - Process ID of the target 64-bit process
- `shellcode_file` - Path to the x64 shellcode binary file

### Example

```
inject-32to64 1234 /tmp/payload.bin
```

## Requirements

- Current process must be running as WOW64 (32-bit process on 64-bit Windows)
- Target process must be a native 64-bit process (not WOW64)
- Requires `PROCESS_ALL_ACCESS` permissions on target process


## Credits

Based on WOW64 injection techniques for crossing architecture boundaries.

- https://maldevacademy.com/new/modules/64
- https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/migrate/executex64.asm