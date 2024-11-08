# disable the pagination line that shows when script is ran in other ways that "source script" within gdb
# has no effect if ran in gdb itself
gdb.execute("set pagination off")

# delete any previous breakpoints to prevent interference
for bp in gdb.breakpoints():
    bp.delete()

# calls to library functions that are susceptible to a buffer overflow
calls = ["strcpy@plt", "gets@plt"]

# for each of those calls add a potential breakpoint if it exists
for call in calls:
    try:
        bp = gdb.Breakpoint(call)
    except gdb.error as e:
        pass

# begin running
gdb.execute("r")

# for each breakpoint, print bytes to overwrite return address
for b in gdb.breakpoints():

    # ignore breakpoint is pending, i.e. did not find that call when made earlier
    if b.pending:
        continue

    # breakpoint will stop inside the called instruction but we want to be in the caller's stack frame
    gdb.execute("finish")


    # now we can get the buffer source using the calling convention and the address where the eip is saved at
    # subtracting the addresses will give the number of bytes

    inferior = gdb.selected_inferior()
    frame = gdb.selected_frame()

    # get buffer source address by reading off the stack
    esp = gdb.parse_and_eval("$esp")

    stack_bytes = b''
    buffer_address = 0

    # this uses calling convention that destination buffer is last address on stack - can amend for other calling conventions later
    stack_bytes = bytes(inferior.read_memory(esp, 4))
    buffer_address = (stack_bytes[3] << 24) | (stack_bytes[2] << 16) | (stack_bytes[1] << 8) | (stack_bytes[0])

    # get the end of the address where the eip is saved at by getting value of ebp and adding 4 for saved eip address and another 4 to get to the end of it
    saved_iep_address_end = frame.read_register("ebp") + 8

    # calculation and printing
    num_overwrite_bytes = int(saved_iep_address_end) - int(buffer_address)

    print("\ninput string length to overwrite the saved return address:", num_overwrite_bytes, "bytes\n")

    gdb.execute("c")

