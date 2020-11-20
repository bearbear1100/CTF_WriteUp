import string
from pwn import *
from hashlib import sha256

from Cryptodome.Util.number import (bytes_to_long, getStrongPrime, inverse,
                                    long_to_bytes, GCD)

def parse_onion(string) :
    return string.replace('\n','').replace(' ','')

# LEVEL 1

conn = remote('happy-farm.balsnctf.com', 4001)
# conn = remote('localhost', 10001)
conn.recvuntil("My seed:")


out = conn.recvuntil("My start date: ")
SERVICE_SEED = parse_onion(out.strip().decode()[:-14])
SERVICE_IV = conn.recvline().decode().strip()

SEED = hex(bytes.fromhex(SERVICE_SEED[:2])[0] ^ 10)[2:].rjust(2, '0') + SERVICE_SEED[2:]
IV = hex(bytes.fromhex(SERVICE_IV[:2])[0] ^ 10)[2:].rjust(2, '0') + SERVICE_IV[2:]

conn.recvuntil('start date:') 
conn.sendline(IV)
print("my start date: ", IV)

conn.recvuntil('seed') 
conn.sendline(SEED)
print("my seed: ", SEED)

conn.recvuntil('layer') 
layer = 4000
conn.sendline(str(layer))
print("my layer: ", layer)

conn.recvuntil('Your onion') 
out = conn.recvuntil('start date: ')
onion = parse_onion(out.strip().decode()[:-11])
print('my onion:', onion)


IV = onion[-32:]
conn.sendline(onion[-32:])
print("my start date: ", IV)

conn.recvuntil('seed') 
conn.sendline(onion)
print("my seed2: ", onion)

conn.recvuntil('layer') 
layer = 5000
conn.sendline(str(layer))
print("my layer: ", layer)

conn.recvuntil('Your onion') 
out = conn.recvuntil('How would my onion looks like? ')
onion = parse_onion(out.strip().decode()[:-30])
print('my onion:', onion)

conn.sendline(onion)

# LEVEL 2

conn.recvuntil('My seed is')
seed = parse_onion(conn.recvuntil('You should use my seed first!').strip()[:-29].decode())
conn.recvuntil('layer')
conn.sendline('8999')
k1n = pow(1 << 1023,3) - bytes_to_long(bytes.fromhex(seed))
conn.recvuntil('your onion')
onion = parse_onion(conn.recvuntil('You can now use your seed').strip()[:-25].decode())
onion = bytes_to_long(bytes.fromhex(onion))
k2n = pow(onion,3**8997,k1n) - 4479489484355608421114884561136888556243290994469299069799978201927583742360321890761754986543214231552
n = GCD(k1n, k2n)
while True :
    if n % 2 == 0 :
        n = n // 2
    elif n % 3 == 0 :
        n = n // 3
    elif n % 5 == 0 :
        n = n // 5
    elif n % 7 == 0 :
        n = n // 7
    else :
        break
print("n = ", n)
conn.recvuntil('seed: ')
conn.sendline('20000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
conn.recvuntil('layer: ')
conn.sendline('8998')
conn.recvuntil('Here you go')
out = conn.recvuntil('How would my onion looks like? ')
eaten_onion = parse_onion(out.strip().decode()[:-30])
route = "=============================================================================================================================================================================x========xxxx====xx==xxxx==xxxx==xxxxxxxxxxxxx===xxxxxxxxxxxxxxxx==xxxxxxxxxxxxx=xx"
count = 0
onion2 = ""
for idx, symbol in enumerate(route) :
    if route[idx] == '=' :
        onion2 += eaten_onion[count]
        count += 1
    else :
        onion2 += '0'

onion2 = bytes_to_long(bytes.fromhex(onion2))
print()
print(f'coppersmith({n}, 3, {onion2}, {onion})')

conn.sendline(long_to_bytes(onion2 + int(input("x = ?"))).hex())

# Level 3
conn.recvuntil('layer: ')
conn.sendline('192')
conn.recvuntil('your onion')

out = conn.recvuntil('layer: ')
onion = parse_onion(out.strip().decode()[:-6])
print(onion)
conn.sendline('192')
conn.recvuntil('layer: ')
conn.sendline('192')
conn.recvuntil('layer: ')
conn.sendline('192')
conn.recvuntil("How would my onion looks like?")
conn.sendline(onion.replace('x', ''))
conn.interactive()

# BALSN{It_is_W3!rd_Why_c4n_You_P1a4t_Onions_F4om_Seeds_OF_SUNFLOWER?}