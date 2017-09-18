from pwn import * # pip install pwntools
from random import *
from luhn import * # pip install luhn

# CSAW 2017 Misc 100- CVV
# Problem: nc misc.chal.csaw.io 8308
# Initial Prompt:
"""
I need a new Visa!
4444333322221111
Thanks!
I need a new MasterCard!
4444333322221111
Hmmmmm that doesn't seem correct...
"""
"""
I need a new American Express!
1234
That's not even the right amount of numbers...
"""

# Connect to remote server
r = remote("misc.chal.csaw.io", 8308)

# Luhn algorithm (modulus 10)
# First 6 digits issuer identification number (IIN) Find list of known IIN prefixes
# Next is account number 6-12 digits in length
# Last digit is a check digit calculated from the previous digits
# https://go.eway.io/s/article/ka828000000L1PdAAK/Test-Credit-Card-Numbers
# CVN for testing for Visa/Mastercard is any 3 digits
# CVN for American Express is any 4 digits
# visa = "4444333322221111" # 4111111111111111 Card numbers start with a 4 and are 16 digits in length
# mastercard = "5105105105105100" # 5500000000000004 Card numbers start with numbers 51-55 and are 16 digits in length
# express = "378282246310005" # 340000000000009 Card numbers begin with 34 or 37 and are 15 digits in length
# discover = "6011000000000004" # Card numbers begin with 6011 or 65 and are 16 digits in length
# checkLuhn will return True or False if input is a valid credit card number 
# Fails on < 16 digit check, Just re-run the script if it fails 
def checkLuhn(purportedCC=''):
    sum = 0
    parity = len(purportedCC) % 2
    for i, digit in enumerate([int(x) for x in purportedCC]):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        sum += digit
    return sum % 10 == 0

# Generates random credit card numbers. Takes in starting IIN and number length
def gen_cred(IIN, length):
    credit = str(IIN)
    # length - 1 random integers appended after IIN
    while len(credit) < length - 1:
        acct_num = randint(0, 9)
        credit = credit + str(acct_num)
    credit = credit[::-1]
    temp = ""
    sum = 0
    # Starting from the right side, every other number is doubled and then added to a sum of all numbers, if > 9 the digits are added together to the sum
    for i in xrange(0, length - 1):
        double_value = 0
        if i % 2 == 0:
            double_value = 2 * int(credit[i])
            if double_value > 9:
                temp = str(double_value)
                sum = sum + int(temp[0]) + int(temp[1])
            else:
                sum = sum + double_value
        else:
            sum = sum + int(credit[i])
    # Finding 'x' value to make sum divisible by 10, this value is the final digit of the credit card number
    checkten = sum % 10
    if checkten != 0:
        checkten = 10 - checkten
    credit = credit[::-1]
    credit = credit + str(checkten)
    return credit
 
# Loop until done
while True:
    # Initial Prompt:
    line = r.recvline()
    print line
    if line == 'I need a new MasterCard!\n':
        mastercard = gen_cred(51, 16)
        print mastercard
        r.sendline(mastercard)
    elif line == 'I need a new American Express!\n':
        express = gen_cred(34, 15)
        print express
        r.sendline(express)
    elif line == 'I need a new Visa!\n':
        visa = gen_cred(4, 16)
        print visa
        r.sendline(visa)
    elif line == 'I need a new Discover!\n':
        discover = gen_cred(6011, 16)
        print discover
        r.sendline(discover)
    elif 'I need a new card that starts with' in line:
        line = line[:-1]
        line = line[:-1]
        word_list = line.split()
        new_card = gen_cred(int(word_list[-1]), 16)
        print new_card 
        r.sendline(new_card)
    elif 'I need a new card which ends with' in line:
        line = line[:-1]
        line = line[:-1]
        word_list = line.split()
        brute_gen = gen_cred(randint(1,100), 16)
        while brute_gen.endswith(word_list[-1]) != True:
            brute_gen = gen_cred(randint(1,100), 16)
        print brute_gen
        r.sendline(brute_gen)
    elif 'I need to know if' in line:
    # I need to know if 7741563169713357 is valid! (0 = No, 1 = Yes)
        word_list = line.split()
        check_value = verify(word_list[5]) #checkLuhn(word_list[5])
        if check_value == True:
            r.sendline('1')
        elif check_value == False:
            r.sendline('0') 
        print r.recvline()
    print r.recvline()

# flag{ch3ck-exp3rian-dat3-b3for3-us3}
