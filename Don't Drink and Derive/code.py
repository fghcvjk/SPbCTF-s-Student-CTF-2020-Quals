import struct 
import sys
from Crypto.Cipher import AES

ROUND_NUM = 109

def pad(string, blocksize):
    to_add = blocksize - (len(string) % blocksize)
    return string + b"\x00"*to_add

def as_128bit_int(data):
    b, a = struct.unpack("<QQ", data)
    return (a << 64) | b

def int128_to_bytes(val):
    mx = 0xFFFFFFFFFFFFFFFF
    return struct.pack('<QQ', val & mx, (val >> 64) & mx,)

def calc_sum(incoming):
    padded = pad(incoming, 16)
    blocks = len(padded) // 16
    csum = 0
    for i in range(blocks):
        csum = csum ^ as_128bit_int(padded[16*i: 16*i + 16])
    return csum


def tr(val):
    bits = bin(val)[2:]
    bits = bits.rjust(128, "0")
    s = ""
    tr = [82, 113, 80, 2, 16, 85, 3, 43, 36, 73, 110, 92, 94, 56, 39, 90, 127, 61, 62, 28, 52, 5, 105, 118, 15, 1, 74, 83, 31, 95, 59, 54, 6, 79, 84, 14, 63, 112, 111, 27, 23, 101, 46, 4, 22, 76, 49, 88, 50, 19, 9, 122, 66, 10, 13, 30, 116, 81, 42, 65, 8, 26, 41, 21, 17, 33, 98, 44, 108, 69, 120, 18, 124, 57, 78, 102, 126, 68, 47, 107, 117, 35, 93, 100, 86, 99, 51, 25, 87, 104, 38, 34, 123, 0, 45, 7, 11, 12, 24, 114, 58, 71, 96, 77, 75, 119, 20, 89, 97, 64, 53, 37, 106, 55, 60, 115, 91, 40, 32, 70, 29, 103, 109, 125, 121, 48, 67, 72]
    for i in tr:
        s += bits[i]
    return int(s, 2)

def kdf(key_material):
    key_n = calc_sum(key_material)
    MOD = 2**128
    for i in range(ROUND_NUM):
        key_n = key_n + 0xbebafeca
        key_n = key_n * 0x2717
        key_n = key_n ^ 0xd76aa478
        key_n = key_n * 0xfe
        key_n = key_n - 0xffeff47d02441453
        key_n = key_n * 0x4321
        key_n = key_n % MOD
    key = tr(key_n);
    key = key * 0xebd68935ca0313d6035cb04d8ab2a0dd
    key = tr(key)
    key = key * 0xc57083072226e8c12199015ec56a1e09
    key = tr(key)
    key = key * 0x796d68ac676e7d89eef1e2f1c04459b
    key = tr(key)
    return int128_to_bytes(key)

if __name__ == "__main__":
    key = kdf(sys.argv[1].encode('latin-1'))
    with open(sys.argv[2], "rb") as f:
        to_encrypt = f.read()
    aes = AES.new(key, AES.MODE_ECB)
    to_encrypt = pad(to_encrypt, 16)
    encrypted = aes.encrypt(to_encrypt)
    with open(sys.argv[2] + ".enc", "wb") as f:
        f.write(encrypted)

