from openfhe import *

parameters = CCParamsCKKSRNS()

secret_key_dist = SecretKeyDist.UNIFORM_TERNARY
parameters.SetSecretKeyDist(secret_key_dist)

parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
parameters.SetRingDim(1<<12)

if get_native_int()==128:
    rescale_tech = ScalingTechnique.FIXEDAUTO
    dcrt_bits = 78
    first_mod = 89
else:
    rescale_tech = ScalingTechnique.FIXEDAUTO
    dcrt_bits = 40
    first_mod = 40

parameters.SetScalingModSize(dcrt_bits)
parameters.SetScalingTechnique(rescale_tech)
parameters.SetFirstModSize(first_mod)

level_budget = [4, 4]

levels_available_after_bootstrap = 100

depth = levels_available_after_bootstrap + FHECKKSRNS.GetBootstrapDepth(level_budget, secret_key_dist)

print(depth)

parameters.SetMultiplicativeDepth(depth)

cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)
cc.Enable(PKESchemeFeature.ADVANCEDSHE)
cc.Enable(PKESchemeFeature.FHE)

ring_dim = cc.GetRingDimension()
# This is the mazimum number of slots that can be used full packing.

num_slots = int(ring_dim / 2)
print(f"CKKS is using ring dimension {ring_dim}")

cc.EvalBootstrapSetup(level_budget, slots=num_slots)

keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)
cc.EvalBootstrapKeyGen(privateKey=keys.secretKey,  slots=num_slots)


def decrypt(a, sk):
    result = cc.Decrypt(a,sk)
    #print(result)
    result.SetLength(num_slots)
    return  result.GetCKKSPackedValue()[0].real

N = 5

matriz_exemplo = [[1.03, 1.1, -1.2 ,1.13, 1], [1.1, 1, -1.3 ,1.41, 2], [1.3, 1.2, 1 , 1.56, 1.5 ], [1.12, 1.9, 1, 1.12, 1.9], [1.2, 1.98, 1.08, 1.18, 1.98]]
b_exemplo = [1.19, -1.9, 1.5, 1.5, 1.7]

encoded_A = []
encoded_B = []

for i in range(len(b_exemplo)):
    encoded_A.append([])
    encoded_B.append(cc.MakeCKKSPackedPlaintext([b_exemplo[i]]))
    encoded_B[i].SetLength(num_slots)
    for j in range(len(b_exemplo)):
        encoded_A[i].append(cc.MakeCKKSPackedPlaintext([matriz_exemplo[i][j]]))
        encoded_A[i][j].SetLength(num_slots)

# Encrypt the encoded vectors

encrypted_A = []
encrypted_B = []

for i in range(len(b_exemplo)):
    encrypted_A.append([])
    encrypted_B.append(cc.Encrypt(keys.publicKey, encoded_B[i]))
    for j in range(len(b_exemplo)):
        encrypted_A[i].append(cc.Encrypt(keys.publicKey, encoded_A[i][j]))

print(f"Initial number of levels remaining: {depth - encrypted_A[0][0].GetLevel()}")

############ GAUSS

def divisao_linha(h, divisor, m):
    for i in range(m):
        d = cc.EvalDivide(divisor, 1,1024,129)
        print("level before bootstrap d", depth - d.GetLevel())
        h[i] = cc.EvalMult(h[i],d)
        #h[i] = cc.EvalBootstrap(h[i])
        print("level after bootstrap d", depth - d.GetLevel())
    return h


def subtracao(h1, h2, coef, m):
    for i in range(m):
        h1[i] = cc.EvalSub(h1[i], cc.EvalMult(h2[i], coef))
        #h1[i] = cc.EvalBootstrap(h1[i])

    return h1

def gauss(matrix, b, M):
    for i in range(M):
        matrix[i] = divisao_linha(matrix[i], matrix[i][i], M)
        for j in range(M):
            if (i != j):
                #b[j] -= b[i] * matrix[j][i]
                b[j] = cc.EvalSub(b[j], cc.EvalMult(b[i], matrix[j][i]))
                #b[j] = cc.EvalBootstrap(b[j])
                matrix[j] = subtracao(matrix[j], matrix[i], matrix[j][i], M)
    return b

gauss(encrypted_A, encrypted_B, len(b_exemplo))

print(f"Number of levels remaining: {depth - encrypted_A[0][0].GetLevel()}")

############

decrypted_A = []
decrypted_B = []

for i in range(len(b_exemplo)):
    decrypted_A.append([])
    print(i)
    decrypted_B.append(decrypt(encrypted_B[i], keys.secretKey))
    # for j in range(len(b_exemplo)):
    #     decrypted_A[i].append(decrypt(encrypted_A[i][j], keys.secretKey))


print(decrypted_A)
print(decrypted_B)
# result = cc.Decrypt(c_add,keys.secretKey)
# result.SetLength(batch_size)
# print("c1 + c2 = " + str(result))









