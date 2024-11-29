import argparse

import auto_rop_gen as execve_rop_gen
import run_shellcode_rop as shellcode_rop_gen

import subprocess

parser = argparse.ArgumentParser(
    description="SSS-Coursework Main",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)
parser.add_argument("--overflow-length", default=-1, type=int)
parser.add_argument("--execve-gen-exploit", default=False, type=bool)
parser.add_argument("--shellcode-gen-exploit", default=False, type=bool)
parser.add_argument("--program", default=None, type=str)

minifuzzer_bash_filename = "overflowlength.sh"

def main(args):

    if args.program == None:
        print("Please enter program name!\nExitting.")
        return
    
    program_name = args.program

    # first get overflow length

    overflow_length = 0

    if args.overflow_length == -1:
        # use the minifuzzer program to automatically find overflow length

        overflow_length = int(subprocess.check_output([f"./{minifuzzer_bash_filename}", program_name])[:-1])

    else:
        if args.overflow_length < -1:
            print("Invalid buffer overflow length!\nExitting.")
            return
        overflow_length = args.overflow_length

    # generate exploits

    if args.execve_gen_exploit:
        # call script appropriately

        print("Generating ROP Chain for execve.")

        badfile_name = execve_rop_gen.gen(overflow_length)

        print("Generated ROP chain in", badfile_name)
    
    if args.shellcode_gen_exploit:
        # call script appropriately

        print("Generating ROP Chain for shellcode.")

        badfile_name = shellcode_rop_gen.gen(overflow_length)

        print("Generated ROP chain in", badfile_name)
    
    print("Completed exploit generation.\nExitting.")


if __name__ == "__main__":
    args, _ = parser.parse_known_args()
    main(args)
