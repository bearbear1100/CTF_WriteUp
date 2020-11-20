import os
import sys

from Cryptodome.Cipher import AES
from Cryptodome.Util.number import (bytes_to_long, getStrongPrime, inverse,
                                    long_to_bytes)


class Fertilizer1:
    start_date = None
    key = None

    def __init__(self, start_date=None):
        if Fertilizer1.start_date is None:
            Fertilizer1.start_date = os.urandom(16)

        if Fertilizer1.key is None:
            Fertilizer1.key = os.urandom(16)

        self.key = Fertilizer1.key
        self.start_date = Fertilizer1.start_date
        if not start_date is None:
            self.start_date = start_date

        self.fertilizer = AES.new(mode=AES.MODE_CBC, key=self.key, iv=self.start_date)

    def grow(self, seed, layer):
        for _ in range(layer):
            seed = self.fertilizer.encrypt(seed)
        return seed


class Fertilizer2:
    def __init__(self):
        self.e = 3
        self.p = getStrongPrime(512, e=self.e)
        self.q = getStrongPrime(512, e=self.e)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.d = inverse(self.e, self.phi)

        ## generate secret seed
        self.seed = pow(1 << 1023, self.e, self.n)
        self.seed = long_to_bytes(self.seed)

    def grow(self, seed, layer):
        exp = pow(self.d, layer, self.phi)
        seed = bytes_to_long(seed)
        if seed >= self.n or seed < 0:
            raise Exception

        onion = pow(seed, exp, self.n)
        return long_to_bytes(onion)


class Fertilizer3:
    key = None

    def __init__(self):
        if Fertilizer3.key is None:
            Fertilizer3.key = os.urandom(32)
        self.key = Fertilizer3.key
        self.rc4_init()

    def rc4_init(self):
        self.i = 0
        self.j = 0

        s = []
        for i in range(256):
            s.append(i)

        j = 0
        for i in range(256):
            j += s[i] + self.key[i % 16]
            j %= 256

            s[i], s[j] = s[j], s[i]

        self.s = s

    def swap(self, a, b):
        a, b = b, a

    def bytes_xor(self, a, b):
        return bytes([_a ^ _b for _a, _b in zip(a, b)])

    def rc4_encrypt(self, inputs):
        output = []
        i = self.i
        j = self.j
        s = self.s
        for _ in range(len(inputs)):
            i = (i + 1) % 256
            j = (j + s[i]) % 256
            self.swap(s[i], s[j])
            output.append(s[(s[i] + s[j]) % 256])

        self.i = i
        self.j = j
        self.s = s
        return self.bytes_xor(inputs, output)

    def encrypt(self, L, R):
        next_L = R
        next_R = self.bytes_xor(L, self.rc4_encrypt(R))
        return next_L, next_R

    def grow(self, seed, layer):
        length = len(seed) // 2
        L, R = seed[:length], seed[length:]
        for _ in range(layer):
            L, R = self.encrypt(L, R)
        return L + R

    def doctor_Balsn(self, seed, layer):
        r"""
        Dr. Balsn is our secret think tank!
        It can help us to grow onions incredibly fast on our server.
        We won't let you to access it!!!
        """
        raise NotImplementedError
