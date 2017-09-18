# pip install pwntools
from pwn import *

# CSAW 2017 Misc 50- Serial
# Problem: nc misc.chal.csaw.io 4239
# Initial Prompt:
"""
8-1-1 even parity. Respond with '1' if you got the byte, '0' to retransmit.
01110011001
"""

# 11 bits: Start bit = 0, 8 bits of data, parity bit, stop bit = 1

# Connect to remote server
r = remote("misc.chal.csaw.io", 4239)

# Initial Prompt:
print r.recvuntil('retransmit.', drop=False)
print r.recvline()

# Strings used to store conversion from binary to ascii
temp = ""
binary = ""
convert = ""
flag = ""

# Loop until done
while True:
    count = 0
    serial = r.recvline()
    # Check for even number of 1's in data including the parity bit
    for i in xrange(1,10):
        if serial[i] == '1':
            count = count + 1
    if count % 2 == 0:
        temp = serial[1:] # Drop the start bit
        binary = temp[:8] # Drop the parity and stop bits
        convert = int(binary, 2) # Convert binary to decimal
        # Use chr() function to receive ascii representation of integer value and append to flag
        flag = flag + chr(convert)
        # Receive flag
        print flag
        r.sendline('1')
    else:
        r.sendline('0')

# flag{@n_int3rface_betw33n_data_term1nal_3quipment_and_d@t@_circuit-term1nating_3quipment}
