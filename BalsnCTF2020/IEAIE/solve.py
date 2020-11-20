import base64
import numpy as np
from PIL import Image
import string
from pwn import *
from lib import *
from hashlib import sha256

M, N = shape = (260, 260)
COUNTER = 0

DEBUG = True
if DEBUG :
    conn = remote('localhost', 10000)
else :
    conn = remote('ieaie-ap.balsnctf.com', 7122)
    conn.recvuntil('sha256(')
    prefix = conn.recvuntil(' ').strip().decode()
    difficulty = 22
    zeros = '0' * difficulty

    def is_valid(digest):
        if sys.version_info.major == 2:
            digest = [ord(i) for i in digest]
        bits = ''.join(bin(i)[2:].zfill(8) for i in digest)
        return bits[:difficulty] == zeros
    ans = ''
    i = 0
    while True:
        i += 1
        s = prefix + str(i)
        if is_valid(hashlib.sha256(s.encode()).digest()):
            ans = str(i)
            break
    print(conn.recvuntil('??? = '))
    conn.sendline(ans)

def GetRandomSameEntropyImage(F) :
    m,n = F.shape
    P = np.random.permutation(m*n)
    A = F.reshape(-1)[P]
    return A.reshape(m, n)

def rollbackR(R, up, vp):
    W = np.zeros(C.shape, dtype='uint8')
    for i in range(M):
        for j in range(N):
            W[i][j] = (M*N+(i+1)+(j+1)) % 256
    B = (R-W) % 256
    A = np.zeros(C.shape, dtype='uint8')
    tmp = np.zeros(C.shape, dtype='uint8')
    for i in range(M):
        tmp[i, :] = B[vp[i], :]
    for i in range(N):
        A[:, i] = tmp[:, up[i]]
    return A

def swap(F, x1, x2) :
    I = F.copy()
    i1,j1 = x1
    i2,j2 = x2
    I[i2][j2], I[i1][j1] = I[i1][j1] , I[i2][j2]
    return I

def to(F, x1, n) :
    I = F.copy()
    i, j = x1
    I[i][j] = n
    return I

def findDiff(c1,c2) :
    return [idx for idx, c in enumerate(sum(c1.T==c2.T)) if c != 260 ]

def saveImg(name, size, img_bytes) :
    eflag = Image.frombytes('L', size, img_bytes)
    eflag.save(f'images/{name}','bmp')
    return eflag

def loadImg(byte, M, N):
    F = np.fromstring(byte, np.uint8)
    F = F.reshape(M, N)
    return F

# Init
conn.recvuntil('Generating new key and flag (260x260)...')
conn.recvuntil('Encrypted flag (flag.bmp):\n')
img = base64.b64decode(conn.recvline().strip())
saveImg("eflag.bmp", (M,N), img)
CFLAG = loadImg(img, M, N)

conn.recvuntil('Image with the same entropy (image.bmp):\n')
F1 = base64.b64decode(conn.recvline().strip())
saveImg("image.bmp", (M,N), F1)
F1 = loadImg(F1, M, N)

def Encrypt(image, M=M, N=N) :
    global COUNTER 
    COUNTER  += 1
    conn.recvuntil('Gimme the image size M> ')
    conn.sendline(str(M))
    conn.recvuntil('Gimme the image size N> ')
    conn.sendline(str(N))
    conn.recvuntil('Gimme the base64 encoded image> ')
    conn.sendline(base64.b64encode(image).decode())
    img_str = base64.b64decode(conn.recvline().strip())
    return loadImg(img_str, M, N)

s1 = Entropy(F1)
C1 = Encrypt(F1)

x = 0
y = 0
NEXT = False
most_uni = -1
most_col = -1
for col in range(M) :
    uni = len(np.unique(F1[:, col]))
    if uni > most_uni :
        most_col = col
print("Most different element in column :", most_col)
for i in range(260) :
    for j in range(260) :
        if F1[i][most_col] == F1[j][most_col] :
            continue
        print(F1[i][most_col], F1[j][most_col])
        NEXT = True
        x = i
        y = j
        # break
    if NEXT : break
# Find up[COL] = 0
print("\n Challenge start ...")

# if col transform to 0 -> ds will not change, we can calculate vp easily
print("Brute force up[?] = 0")
COL = -1
for col in range(0,260) :
    F2 = swap(F1, (x,col), (y,col))
    C2 = Encrypt(F2)
    if np.array(sum(C1.T == C2.T)).tolist().count(260) == 258 :
        COL = col
        break
assert COL != -1, "Not found."

print(f"Find up[{COL}] = 0")
print(f"Connect count : {COUNTER}", end='\n\n')

print("Start to get vp ...")
# GET VP (1)
# VP = [-1] * m
# for x in range(256): 
#     for y in range(256): 
#         if F1[x][UP[COL]] == y : 
#             continue 
#         F2 = to(F1,(x,COL),y) 
#         s2 = Entropy(F2) 
#         if s1 == s2 : 
#             *_,D2,B2,R2,C2 = Encrypt(F2) 
#             VP[x] = findDiff(C2, C)[0]
#             if not (-1 in VP) : break
#     if not (-1 in VP) : break

# Get VP (2) - swap will never change entropy
VP = [-1] * M
for x in range(M) :
    candi = []
    for c in range(N) :
        if F1[x][COL] != F1[c][COL] and VP[c] == -1:
            candi.append(c)
    
    if len(candi) < 2 :
        continue

    ROW = []
    X_FIND = False
    lastY = -1
    for y in candi :
        F2 = swap(F1, (x,COL), (y,COL))
        C2 = Encrypt(F2)
        b1, b2 = findDiff(C1, C2)
        if not X_FIND :
            if lastY == -1 :
                lastY = y
            else :
                if b1 in ROW :
                    VP[x] = b1
                    ROW.remove(b1)
                    VP[lastY] = ROW[0]
                    ROW = [b1]
                else :
                    VP[y] = b1
                if b2 in ROW :
                    VP[x] = b2
                    ROW.remove(b2)
                    VP[lastY] = ROW[0]
                    ROW = [b2]
                else:
                    VP[y] = b2
                X_FIND = True
                continue
            ROW.append(b1)
            ROW.append(b2)
        else :
            if b1 in ROW :
                VP[y] = b2 
            else :
                VP[y] = b1
        if VP.count(-1) == 0 : break
    if VP.count(-1) == 0 : break
print("vp get.")
print(f"Connect count : {COUNTER}", end='\n\n')

print("Start to get UP ...")
# Try to get UP
UP = [-1] * N
UP[COL] = 0
for x in range(M) :
    for y in range(N) :
        for U in range(256) :
            if F1[x][y] == U :
                continue
            if UP[y] != -1 :
                continue
            F2 = to(F1, (x,y), U)
            # F2 = swap(F1, (x,COL), (y,COL))
            s2 = Entropy(F2)
            if s1 == s2 : 
                C = C1.copy()
                C2 = Encrypt(F2)
                for i in range(N-1, -1, -1) :
                    for d in range(256) :
                        tmp1 = C[:, i] - d * C[:, i-1]
                        tmp2 = C2[:, i] - d * C2[:, i-1]
                        if sum(tmp1 == tmp2) == N :
                            C[:, i] = tmp1
                            C2[:, i] = tmp2
                            break
                    else :
                        print(f"Find {y} -> {i}, ", UP.count(-1), "Remain ...")
                        UP[y] = i
                        break
        if UP.count(-1) == 0 : break
    if UP.count(-1) == 0 : break

print("up get.")
print(f"Connect count : {COUNTER}", end='\n\n')

# After Getting UP + VP, we can calculate A -> "R" and "ds" by ourselves.
def calculateR(A, up, vp):
    B = np.zeros(A.shape, dtype='uint8')
    tmp = np.zeros(A.shape, dtype='uint8')
    for i in range(N):
        tmp[:, up[i]] = A[:, i] # col
    for i in range(M):
        B[vp[i], :] = tmp[i, :] # row
    
    W = np.zeros(A.shape, dtype='uint8')
    for i in range(M):
        for j in range(N):
            W[i][j] = (M*N+(i+1)+(j+1)) % 256
    R = (B+W) % 256
    return R

def calculateDS(R):
    column_count = np.zeros((N-1, 256), dtype=int)
    for a, z in zip(column_count, R[:, 1:].T):
        v, c = np.unique(z, return_counts=True)
        a[v] = c
    counts = np.cumsum(column_count[::-1], axis=0)[::-1]
    ent = entropy(counts, base=2, axis=-1)
    ds = np.ceil(ent*(10**14)) % N
    ds = np.concatenate([ds, [0]]).astype(int)
    return ds

print("Calculate Key ...")
KLIST = [-1] * N
K = np.zeros(F1.shape, dtype='uint8')
from Crypto.Util.number import inverse, GCD

# Recover K
while -1 in KLIST :
    TF = GetRandomSameEntropyImage(F1)
    TC = Encrypt(TF)
    TR = calculateR(TF, UP, VP)
    TD = calculateDS(TR)
    D = np.zeros(F1.shape, dtype='uint8')
    # D[:, ?] = (TD[?]+1)*K[:, ?]+K[:, TD[?]]
    for i, d in enumerate(TD):
        if i == 0:
            D[:, i] = (TC[:, i] - TR[:, i]) % 256
        else:
            D[:, i] = (TC[:, i] - TR[:, i] - (d+1)*TC[:, i-1]) % 256
    for i in range(M) :
        # Check i
        if KLIST[i] != -1 and KLIST[TD[i]] != -1 :
            pass
        elif KLIST[i] != -1 and KLIST[TD[i]] == -1 :
            # D[:, ?] = (TD[?]+1)*K[:, ?]+K[:, TD[?]]
            K[:, TD[i]] = (D[:, i] - (TD[i]+1)*K[:, i]) % 256
            KLIST[TD[i]] += 1 
        elif KLIST[i] == -1 and KLIST[TD[i]] != -1 :
            # D[:, i] = (TD[i]+1)*K[:, i]+K[:, TD[i]]
            if GCD(TD[i]+1, 256) == 1 :
                inv_mul = inverse(TD[i]+1,256)
                K[:, i] = inv_mul * (D[:, i] - K[:, TD[i]])
                KLIST[i] += 1 
        for j in range(N) :
            # Check j
            if KLIST[j] != -1 and KLIST[TD[j]] != -1 :
                pass
            elif KLIST[j] != -1 and KLIST[TD[j]] == -1 :
                # D[:, ?] = (TD[?]+1)*K[:, ?]+K[:, TD[?]]
                K[:, TD[j]] = (D[:, j] - (TD[j]+1)*K[:, j]) % 256
                KLIST[TD[j]] += 1 
            elif KLIST[j] == -1 and KLIST[TD[j]] != -1 :
                # D[:, j] = (TD[j]+1)*K[:, j]+K[:, TD[j]]
                if GCD(TD[j]+1, 256) == 1 :
                    inv_mul = inverse(TD[j]+1,256)
                    K[:, j] = inv_mul * (D[:, j] - K[:, TD[j]])
                    KLIST[j] += 1 

            if TD[i] == j and TD[j] == i :
                # D[:, i] = (TD[i]+1)*K[:, i]+K[:, TD[i]]
                # D[:, j] = (TD[j]+1)*K[:, j]+K[:, TD[j]]
                nKi = (i+1)*D[:, i] - D[:, j] # = (i+1)((j+1)*K[:, i] + K[:, j]) - (i+1)*K[:, j] + K[:, i] = ((i+1)*(j+1) - 1)*K[:, i]
                mult = (i+1)*(j+1)-1
                if GCD(mult,256) != 1 :
                    continue
                inv_mul = inverse(mult,256)
                Ki = nKi * inv_mul % 256
                K[:, i] = Ki
                KLIST[i] += 1 

    print(KLIST.count(-1), "Columns remain...")
print("Recover the secret key.")
print(f"Connect count : {COUNTER}", end='\n\n')

def reverseC(C, K) :
    R = np.zeros(C.shape, dtype='uint8')
    d = 0
    for i in range(N-1, -1, -1):
        if i == 0:
            # for d in range(256) :
            R[:, i] = (C[:, i]-(d+1)*K[:, i]-K[:, d]) % 256
        else:
            R[:, i] = (C[:, i]-(d+1)*C[:, i-1]-(d+1)*K[:, i]-K[:, d]) % 256
            c = np.unique(R[:, i:], return_counts=True)  
            counts = np.cumsum(c[::-1], axis=0)[::-1]
            ent = entropy(counts, base=2, axis=-1)
            d = np.ceil(ent*(10**14)) % N
            d = int(d[1])
    return R

print("Decrypt the encrypted flag...")
RFLAG = reverseC(CFLAG, K)
PFLAG = rollbackR(RFLAG, UP, VP) # OK

print("GET THE FLAG !!")
saveImg("decrypt_eflag.bmp", (M,N), PFLAG)
print(f"Connect count : {COUNTER}", end='\n\n')

conn.close()