# sss-coursework

This tool lets you generate ROP based exploits by automating:

- finding length of buffer overflow until return address is overwritten
- generating ROP based exploit for arbitrary command line for execve
- generating ROP based exploit to execute arbitrary shellcode

Usage:

```
$ python3 main.py --overflow-length=<overflow_length> --execve-gen-exploit --shellcode-gen-exploit --program=<program_file_name> --shellcode=<shellcode_file_name>
```
All arguments except `--program` are optional.

`--overflow-length` specifies the buffer overflow length (if you know it), otherwise exluding it performs simple fuzzing to find the buffer overflow length automatically

`--execve-gen-exploit` will create a file called `badfile_execve` containing the ROP code which will execute the input execve command.

`--shellcode-gen-exploit` will create a file called `badfile_shellcode` containing the ROP code which will execute the shellcode. It will look for the shellcode in the file specified by `<shellcode_file_name>` else will default to looking in `shellcode.bin`.


Examples:

- Example 1: program is vuln3-32 which takes command line argument of a file that it reads and strcpy's into buffer

Run:

```
$ python3 main.py --execve-gen-exploit --shellcode-gen-exploit --program=vuln3-32 --shellcode=shellcode.bin
```

Follow the printed instruction to enter the command to execve. This will generate `badfile_execve` and `badfile_shellcode`. Then run:

```
$ ./vuln-32 badfile_execve
```

to run the execve ROP exploit and run:

```
$ ./vuln-32 badfile_shellcode
```

to run the shellcode ROP based exploit. The shellcode in this example simply runs a shell by execve'ing /bin/sh.

- Example 2: program is 'stack' which directly reads 'badfile' and strcpy's into buffer

Run:

```
$ python3 main.py --execve-gen-exploit --shellcode-gen-exploit --program=stack --shellcode=shellcode.bin
```

Follow the printed instruction to enter the command to execve. This will generate `badfile_execve` and `badfile_shellcode`. Then run:

```
$ cp badfile_execve input
$ ./stack
```

to run the execve ROP exploit and run:

```
$ cp badfile_shellcode input
$ ./stack
```

to run the shellcode ROP based exploit. The shellcode in this example simply runs a shell by execve'ing /bin/sh.
