import re
#from pwn import cyclic, cyclic_find
# Normally i would import pwn however, due to 100 million conda configurations and 50 million mamba configurations, i can't be arsed to fight it


# disable the pagination line that shows when script is ran in other ways that "source script" within gdb
# has no effect if ran (the script, that is) in gdb itself
gdb.execute("set pagination off")
# tells gdb to f off with confirmation prompts
gdb.execute("set confirm off")

# gotta flip the endianness of address because of stack bs
def flip_endianness(address):
    hex_str = format(address)
    # Split the hexadecimal string into bytes and reverse the order
    flipped_hex_str = ''.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)]))
    return flipped_hex_str


# Cartesian product of the charset with itself 4 times
# Edit length default to whatever the len of charset is
# 62**4 is complete overkill.
def cyclic(length=52**4):
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    charset_length = len(charset)
    for i in range(length):
        p1 = i % charset_length
        p2 = (i // charset_length) % charset_length
        p3 = (i // charset_length // charset_length) % charset_length
        p4 = (i // charset_length // charset_length // charset_length) % charset_length
        yield (
            charset[p1] +
            charset[p2] +
            charset[p3] +
            charset[p4]
        )

def cyclic_find(address) -> int:
    print("This process is quite slow! Let it cook")
    address = flip_endianness(address)
    cyclic_list = list(cyclic())
    for index, i in enumerate(cyclic_list):
        #print(i)
        hex_representation = ''.join(format(ord(char), '02x') for char in i)
        #print("Comparing hex representation " + hex_representation, "with address " + address)
        if hex_representation == address:
            # problem #34: python implicit casting is very, very, very, stupid
            return index
    return -1

# runs the program with given input string and tries to catch any buffer overflow
def execute_program(input_string) -> int:
    # treat anything that isn't the input_file_path as a string to be passed to the program
    if (input_string is not input_file_path):
        gdb.execute("r <<< " + input_string, to_string=True)
        status = gdb.execute("info program", to_string=True)
        if "SIGSEGV" in status:
            print("SIGSEGV was raised on input string")
            address = re.findall(r"Program stopped at 0x([0-9a-fA-f]{8,16})", status)[0]
            print("Address of the error: 0x" + address)
            offset = cyclic_find(address)*4
            if offset <= -1:
                print("Failed to find the offset for a plety amount of reasons")
            return offset
        else:
            print("Input did not cause an error!")
            return -1
    else:
        gdb.execute("r " + input_file_path, to_string=True)
        status = gdb.execute("info program", to_string=True)
        if "SIGSEGV" in status:
            print("SIGSEGV was raised on input string")
            address = re.findall(r"Program stopped at 0x([0-9a-fA-f]{8,16})", status)[0]
            print("Address of the error: 0x" + address)
            offset = cyclic_find(address)*4
            if offset <= -1:
                print("Failed to find the offset for a plety amount of reasons")
            return offset
        else:
            print("Input did not cause an error!")
            return -1

# find all possible addresses of the calls
#def find_all_addresses(call):
#    info = gdb.execute("info functions " + call, to_string=True)
#    addresses = re.findall(r"0x[0-9a-fA-f]{8,16}", info)
#    addresses = list(set(addresses)) # remove duplicates
#    print("addresses found for", call, ":", addresses)
#    return addresses

# input string to the program
input_string = ''.join(cyclic(100))
# change this as required
input_file_path = "input.txt"

# pattern_create.rb does not work because ruby does not work because life sucks
with open(input_file_path, "w") as f:
    f.write(input_string)

offset = execute_program(input_string)
if offset <= -1:
    offset = execute_program(input_file_path)
if offset <= -1:
    print(-1)
    gdb.execute("quit")

print(offset)

gdb.execute("quit")