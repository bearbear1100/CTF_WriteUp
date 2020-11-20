#!/usr/bin/env python3
from lib import *
# from subprocess import *
import numpy as np
import sys
import concurrent.futures
import base64
from scipy.stats import entropy
M,N = shape = (260, 260)
def Encrypt(A):
    # Step 1
    (m, n) = A.shape
    s = Entropy(A)

    x_0, y_0 = UpdateKey1(x0, y0, xp0, yp0, s)
    P_seq = LASM2D(mu, x_0, y_0, m*n)
    P = P_seq.reshape(A.shape)

    # Step 2
    a = np.ceil((x0+y0+1)*(10**7)) % (m)
    b = np.ceil((xp0+yp0+2)*(10**7)) % (n)
    u = P[int(a), :]
    v = P[:, int(b)]
    up = np.ceil(u*(10**14)) % (n)
    vp = np.ceil(v*(10**14)) % (m)
    up = up.astype(int)
    vp = vp.astype(int)
    Uniq(up)
    Uniq(vp)
    B = np.zeros(A.shape, dtype='uint8')
    tmp = np.zeros(A.shape, dtype='uint8')
    for i in range(n):
        tmp[:, up[i]] = A[:, i]
    for i in range(m):
        B[vp[i], :] = tmp[i, :]
    
    # Step 3
    W = np.zeros(A.shape, dtype='uint8')
    for i in range(m):
        for j in range(n):
            W[i][j] = (m*n+(i+1)+(j+1)) % 256
    R = (B+W) % 256
    # Step 4
    xp_0, yp_0 = UpdateKey2(x0, y0, xp0, yp0)
    K_seq = LASM2D(mu, xp_0, yp_0, m*n)
    K = K_seq.reshape(A.shape)
    K = np.ceil(K*(10**14)) % 256
    K = K.astype('uint8')

    # Step 5
    C = np.zeros(A.shape, dtype='uint8')
    column_count = np.zeros((n-1, 256), dtype=int)
    for a, z in zip(column_count, R[:, 1:].T):
        v, c = np.unique(z, return_counts=True)
        a[v] = c
    counts = np.cumsum(column_count[::-1], axis=0)[::-1]
    ent = entropy(counts, base=2, axis=-1)
    ds = np.ceil(ent*(10**14)) % n
    ds = np.concatenate([ds, [0]]).astype(int)

    for i, d in enumerate(ds):
        if i == 0:
            C[:, i] = (R[:, i]+(d+1)*K[:, i]+K[:, d]) % 256
        else:
            C[:, i] = (R[:, i]+(d+1)*C[:, i-1]+(d+1)*K[:, i]+K[:, d]) % 256
    return K, up, vp, ds, R, C


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

def GetRandomSameEntropyImage(F) :
    m,n = F.shape
    P = np.random.permutation(m*n)
    A = F.reshape(-1)[P]
    return A.reshape(m, n)

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

def rollbackR(R, up, vp):
    W = np.zeros(R.shape, dtype='uint8')
    for i in range(M):
        for j in range(N):
            W[i][j] = (M*N+(i+1)+(j+1)) % 256
    B = (R-W) % 256

    A = np.zeros(R.shape, dtype='uint8')
    tmp = np.zeros(R.shape, dtype='uint8')

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

GenerateNewKey()
RAW_FLAG = GenerateNewFlag()
REAL_K, REAL_UP, REAL_VP, REAL_DS, REAL_RFLAG, CIPHER_FLAG = Encrypt(RAW_FLAG)

F1 = GetSameEntropyImage(RAW_FLAG)
s1 = Entropy(F1)
K1, UP1, VP1, D1, R1, C1 = Encrypt(F1)
UP = UP1
VP = VP1
# x = 0
# y = 0
# NEXT = False
# for col in range(260):
#     for i in range(260) :
#         for j in range(260) :
#             if F1[i][col] == F1[j][col] :
#                 continue
#             NEXT = True
#             x = i
#             y = j
#         if NEXT : break
#     if NEXT : break
        
# # Find up[COL] = 0
# print("Brute force up[?] = 0")
# COL = 0
# for col in range(0,260) :
#     F2 = swap(F1, (x,col), (y,col))
#     C2 = Encrypt(F2)
#     if np.array(sum(C1.T == C2.T)).tolist().count(260) == 258 :
#         COL = col
#         break
# print(f"Find up[{COL}] = 0")
# print(f"Connect count : {COUNTER}", end='\n\n')

# # if col transform to 0 -> ds will not change, we can calculate vp easily
# print("Start to get vp ...")

# # GET VP (1)
# # VP = [-1] * m
# # for x in range(256): 
# #     for y in range(256): 
# #         if F1[x][UP[COL]] == y : 
# #             continue 
# #         F2 = to(F1,(x,COL),y) 
# #         s2 = Entropy(F2) 
# #         if s1 == s2 : 
# #             *_,D2,B2,R2,C2 = Encrypt(F2) 
# #             VP[x] = findDiff(C2, C)[0]
# #             if not (-1 in VP) : break
# #     if not (-1 in VP) : break

# # Get VP (2) - swap will never change entropy
# VP = [-1] * M
# for x in range(M) :
#     candi = []
#     for c in range(N) :
#         if F1[x][COL] != F1[c][COL] :
#             candi.append(c)
    
#     if len(candi) < 2 :
#         continue

#     ROW = []
#     X_FIND = False
#     lastY = -1
#     for y in candi :
#         F2 = swap(F1, (x,COL), (y,COL))
#         C2 = Encrypt(F2)
#         b1, b2 = findDiff(C1, C2)
#         if not X_FIND :
#             if lastY == -1 :
#                 lastY = y
#             else :
#                 if b1 in ROW :
#                     VP[x] = b1
#                     ROW.remove(b1)
#                     VP[lastY] = ROW[0]
#                     ROW = [b1]
#                 else :
#                     VP[y] = b1
#                 if b2 in ROW :
#                     VP[x] = b2
#                     ROW.remove(b2)
#                     VP[lastY] = ROW[0]
#                     ROW = [b2]
#                 else:
#                     VP[y] = b2
#                 X_FIND = True
#                 continue
#             ROW.append(b1)
#             ROW.append(b2)
#         else :
#             if b1 in ROW :
#                 VP[y] = b2 
#             else :
#                 VP[y] = b1
#         if VP.count(-1) == 0 : break
#     if VP.count(-1) == 0 : break
# print("vp get.")
# print(f"Connect count : {COUNTER}", end='\n\n')

# print("Start to get UP ...")
# # Try to get UP
# UP = [-1] * N
# UP[COL] = 0
# for x in range(M) :
#     for y in range(N) :
#         for U in range(256) :
#             if F1[x][y] == U :
#                 continue
#             if UP[y] != -1 :
#                 continue
#             F2 = to(F1, (x,y), U)
#             # F2 = swap(F1, (x,COL), (y,COL))
#             s2 = Entropy(F2)
#             if s1 == s2 : 
#                 C = C1.copy()
#                 C2 = Encrypt(F2)
#                 for i in range(N-1, -1, -1) :
#                     for d in range(256) :
#                         tmp1 = C[:, i] - d * C[:, i-1]
#                         tmp2 = C2[:, i] - d * C2[:, i-1]
#                         if sum(tmp1 == tmp2) == N :
#                             C[:, i] = tmp1
#                             C2[:, i] = tmp2
#                             break
#                     else :
#                         print(f"Find {y} -> {i}, ", UP.count(-1), "Remain ...")
#                         UP[y] = i
#                         break
#         if UP.count(-1) == 0 : break
#     if UP.count(-1) == 0 : break
# print("up get.")
# print(f"Connect count : {COUNTER}", end='\n\n')

# After Getting UP + VP
R = calculateR(F1, UP, VP)
ds = calculateDS(R)

print("Calculate Key ...")
D = np.zeros(F1.shape, dtype='uint8')
for i, d in enumerate(ds):
    if i == 0:
        D[:, i] = (C1[:, i] - R[:, i]) % 256
    else:
        D[:, i] = (C1[:, i] - R[:, i] - (d+1)*C1[:, i-1]) % 256

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

# def reverseC(C, K) :
#     R = np.zeros(C.shape, dtype='uint8')
#     for i in range(N-1, -1, -1):
#         if i == 0:
#             R[:, i] = (C[:, i]-D[:, i]) % 256
#         else:
#             R[:, i] = (C[:, i]-(ds[i]+1)*C[:, i-1]-D[:, i]) % 256
#     return R

KLIST = [-1] * 260
K = np.zeros(F1.shape, dtype='uint8')
from Crypto.Util.number import inverse, GCD

# Recover K
while -1 in KLIST :
    TF = GetRandomSameEntropyImage(F1)
    *_, TC = Encrypt(TF)
    TR = calculateR(TF, UP, VP)
    TD = calculateDS(TR)
    D = np.zeros(F1.shape, dtype='uint8')
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
                K[:, TD[j]] = (D[:, j] - (TD[j]+1)*K[:, j]) % 256
                KLIST[TD[j]] += 1 
            elif KLIST[j] == -1 and KLIST[TD[j]] != -1 :
                # D[:, j] = (TD[j]+1)*K[:, j]+K[:, TD[j]]
                if GCD(TD[j]+1, 256) == 1 :
                    inv_mul = inverse(TD[j]+1,256)
                    K[:, j] = inv_mul * (D[:, j] - K[:, TD[j]])
                    KLIST[j] += 1 

            if TD[i] == j and TD[j] == i :
                # D[:, ?] = (TD[?]+1)*K[:, ?]+K[:, TD[?]]
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
    print(KLIST.count(-1))
    # C[:, i] = (R[:, i]+(d+1)*C[:, i-1]+(d+1)*K[:, i]+K[:, d]) % 256





RFLAG = reverseC(CIPHER_FLAG, K)
PFLAG = rollbackR(RFLAG, UP, VP) # OK

print("GET THE FLAG !!")
# saveImg("pflag.bmp", (M,N), PFLAG)
# print(f"Connect count : {COUNTER}", end='\n\n')
# conn.close()