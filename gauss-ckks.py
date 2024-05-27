from openfhe import *

mult_depth = 20
scale_mod_size = 50
batch_size = 16

parameters = CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(mult_depth)
parameters.SetScalingModSize(scale_mod_size)
parameters.SetBatchSize(batch_size)

cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)
cc.Enable(PKESchemeFeature.ADVANCEDSHE)

def decrypt(a, sk):
    result = cc.Decrypt(a,sk)
    result.SetLength(batch_size)
    return  result.GetCKKSPackedValue()[0].real

# print("The CKKS scheme is using ring dimension: " + str(cc.GetRingDimension()))

keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)
cc.EvalRotateKeyGen(keys.secretKey, [1, -2])

N = 4

matriz_exemplo = [[3, -0.1, -0.2 ,13], [0.1, 7, -0.3 ,41], [0.3, -0.2, 0 ,54 ], [12, -0.9, 0, 12]]
b_exemplo = [7.85, -19.3, 71.4, 1090]

encoded_A = []
encoded_B = []

for i in range(N):
    encoded_A.append([])
    encoded_B.append(cc.MakeCKKSPackedPlaintext([b_exemplo[i]]))
    for j in range(N):
        encoded_A[i].append(cc.MakeCKKSPackedPlaintext([matriz_exemplo[i][j]]))

# Encrypt the encoded vectors

encrypted_A = []
encrypted_B = []

for i in range(N):
    encrypted_A.append([])
    encrypted_B.append(cc.Encrypt(keys.publicKey, encoded_B[i]))
    for j in range(N):
        encrypted_A[i].append(cc.Encrypt(keys.publicKey, encoded_A[i][j]))


############ GAUSS

def divisao_linha(h, divisor, m):
    for i in range(m):
        d = cc.EvalDivide(divisor, 1,1090,5)
        h[i] = cc.EvalMult(h[i],d)
    return h


def subtracao(h1, h2, coef, m):
    for i in range(m):
        h1[i] = cc.EvalSub(h1[i], cc.EvalMult(h2[i], coef))

    return h1

def gauss(matrix, b, M):
    for i in range(M):
        matrix[i] = divisao_linha(matrix[i], matrix[i][i], M)
        for j in range(M):
            if (i != j):
                #b[j] -= b[i] * matrix[j][i]
                b[j] = cc.EvalSub(b[j], cc.EvalMult(b[i], matrix[j][i]))
                matrix[j] = subtracao(matrix[j], matrix[i], matrix[j][i], M)
    return b

gauss(encrypted_A, encrypted_B, N)

############

decrypted_A = []
decrypted_B = []

for i in range(N):
    decrypted_A.append([])
    decrypted_B.append(decrypt(encrypted_B[i], keys.secretKey))
    for j in range(N):
        decrypted_A[i].append(decrypt(encrypted_A[i][j], keys.secretKey))

print(decrypted_A)
print(decrypted_B)
print(type(decrypted_B[0]) )
# result = cc.Decrypt(c_add,keys.secretKey)
# result.SetLength(batch_size)
# print("c1 + c2 = " + str(result))









