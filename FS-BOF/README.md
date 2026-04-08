# FS-BOF

Filesystem operations as Beacon Object Files — dir, type, mkdir, copy, move, del, rmdir, pwd, cd — without dropping to cmd.exe or PowerShell.

## dir

Lists files in a specified directory. Supports wildcards (e.g. "C:\Windows\S*"). Optionally, it can perform a recursive list with the /s argument

```
dir <path> [/s]
```

## type

Display contents of a file to beacon output

```
type <path>
```

## mkdir

Create a directory and all intermediate directories

```
mkdir <path>
```

## copy

Copy files to a destination path. Supports wildcards in source and UNC paths

```
copy <src> <dst>
```

## move

Move or rename files. Supports wildcards in source and UNC paths

```
move <src> <dst>
```

## del

Delete files at a specified path. Supports wildcards. File-only; directories are skipped

```
del <path>
```

## pwd

Print the beacon's current working directory

```
pwd
```

## cd

Change the beacon's current working directory. Supports relative paths (`.`, `..`) and UNC paths. Change persists for the lifetime of the beacon session

```
cd <path>
```

## rmdir

Remove an empty directory at a specified path. Supports UNC paths. The directory must be empty

```
rmdir <path>
```
