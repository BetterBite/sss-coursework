import re

# Cartesian product of the charset with itself 4 times
# Edit length default to whatever the len of charset is
def cyclic(length=62**4):
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    charset_length = len(charset)
    for i in range(length):
        p1 = i % charset_length
        p2 = (i // charset_length) % charset_length
        p3 = (i // charset_length // charset_length) % charset_length
        p4 = (i // charset_length // charset_length // charset_length) % charset_length
        yield (
            format(ord(charset[p4]), '02x') +
            format(ord(charset[p3]), '02x') +
            format(ord(charset[p2]), '02x') +
            format(ord(charset[p1]), '02x')
        )

def cyclic_find(address):
    cyclic_list = list(cyclic())
    for i in cyclic_list:
        print(i)
        if int(i, 16) == address:
            return cyclic_list.index(i)//4
    return -1

# runs the program with given input string and tries to catch any buffer overflow
def execute_program(input_string):
    # treat anything that isn't the input_file_path as a string to be passed to the program
    if (input_string is not input_file_path):
        try :
            gdb.execute("r <<< " + input_string, to_string=True)
            print("Input did not cause an error!")
        except gdb.error as e:
            print("Caught error:", e)
            address = re.findall(r"0x[0-9a-fA-f]{8,16}", str(e)).group(0)
            print("Address of the error:", address)
            print(cyclic_find(int(address, 16)))
    else:
        try:
            gdb.execute("r < " + input_file_path, to_string=True)
            print("File input did not cause an error!")
        except gdb.error as e:
            print("Caught error:", e)
            address = re.findall(r"0x[0-9a-fA-f]{8,16}", str(e)).group(0)
            print("Address of the error:", address)
            print(cyclic_find(int(address, 16)))

# find all possible addresses of the calls
#def find_all_addresses(call):
#    info = gdb.execute("info functions " + call, to_string=True)
#    addresses = re.findall(r"0x[0-9a-fA-f]{8,16}", info)
#    addresses = list(set(addresses)) # remove duplicates
#    print("addresses found for", call, ":", addresses)
#    return addresses


print("passed checkpoint 0")
# input string to the program
# TODO: make this binary ffs
input_string = ''.join(cyclic(100))
print("input string:", input_string)
input_file_path = "input"
print("passed checkpoint 1")

# pattern_create.rb does not work because ruby does not work because life sucks
with open(input_file_path, "wb") as f:
    f.write(input_string)

print("passed checkpoint 2")
# disable the pagination line that shows when script is ran in other ways that "source script" within gdb
# has no effect if ran (the script, that is) in gdb itself
gdb.execute("set pagination off")

execute_program(input_string)

gdb.execute("quit")
