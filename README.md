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

`--overflow-length` specifies the buffer overflow length (if you know it), otherwise it performs simple fuzzing to find the buffer overflow length

`--execve-gen-exploit` will create a file called `badfile_execve` containing the ROP code which will execute the input execve command.

`--shellcode-gen-exploit` will create a file called `badfile_shellcode` containing the ROP code which will execute the shellcode. It will look for the shellcode in the file specified by `<shellcode_file_name>` else will default to looking in `shellcode.bin`.
