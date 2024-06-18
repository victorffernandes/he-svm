from openfhe import *

parameters = CCParamsCKKSRNS()
secret_key_dist = SecretKeyDist.UNIFORM_TERNARY
parameters.SetSecretKeyDist(secret_key_dist)

parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
parameters.SetRingDim(1<<10)

# if get_native_int()==128:
#     rescale_tech = ScalingTechnique.FIXEDAUTO
#     dcrt_bits = 78
#     first_mod = 89
# else:
rescale_tech = ScalingTechnique.FLEXIBLEAUTO
dcrt_bits = 50
first_mod = 60

parameters.SetScalingModSize(dcrt_bits)
parameters.SetScalingTechnique(rescale_tech)
parameters.SetFirstModSize(first_mod)

level_budget = [4, 4]

levels_available_after_bootstrap = 60

depth = levels_available_after_bootstrap + FHECKKSRNS.GetBootstrapDepth(level_budget, secret_key_dist)

parameters.SetMultiplicativeDepth(50)

cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)
cc.Enable(PKESchemeFeature.ADVANCEDSHE)
cc.Enable(PKESchemeFeature.FHE)

ring_dim = cc.GetRingDimension()
# This is the mazimum number of slots that can be used full packing.

matriz_exemplo = [[1.9, 1.6, 1.8, 1.1, 0.6], [1.2, 1.9, 1.6, 1.2, 0.7], [1.1, 1.2, 1.9, 1.1, 0.5], [1.2, 1.9, 1.3, 2.3, 1.2], [1.1, 1.2, 1.9, 1.9, 2.4]]
b_exemplo = [1.3, 1.2, 1.7, 1.3, 1.9]

num_slots = int(ring_dim/2)
print(f"CKKS is using ring dimension {ring_dim}")

cc.EvalBootstrapSetup(level_budget, slots=num_slots)

keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)
cc.EvalBootstrapKeyGen(privateKey=keys.secretKey,  slots=num_slots)
cc.EvalRotateKeyGen(keys.secretKey, list(range(-(num_slots + 1), num_slots+ 1)))


def getCipherTextAtSlot(ciphertext,  i):
    mask = [0] * num_slots
    mask[i] = 1

    mask_ciphertext = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(mask))
    result = cc.EvalMultAndRelinearize(ciphertext, mask_ciphertext)

    if i != 0:
        result = cc.EvalRotate(result, i)
    r_merge = [result] * num_slots

    result = cc.EvalMerge(r_merge)
    # print("input", i, decrypt(ciphertext,keys.secretKey))
    # print("result", i, decrypt(result,keys.secretKey))

    return result


def decrypt(a, sk):
    result = cc.Decrypt(a,sk)
    #print(result)
    result.SetLength(len(b_exemplo))
    return  result.GetRealPackedValue()


encoded_A = []
encoded_B = cc.MakeCKKSPackedPlaintext(b_exemplo)

for i in range(len(b_exemplo)):
    encoded_A.append(cc.MakeCKKSPackedPlaintext(matriz_exemplo[i]))
    encoded_A[i].SetLength(num_slots)

# Encrypt the encoded vectors

encrypted_A = []
encrypted_B = cc.Encrypt(keys.publicKey, encoded_B)

for i in range(len(b_exemplo)):
    encrypted_A.append(cc.Encrypt(keys.publicKey, encoded_A[i]))

#print(f"Initial number of levels remaining: {depth - encrypted_A[0][0].GetLevel()}")

############ GAUSS

def divisao_linha(h, divisor):
    d = cc.EvalMultAndRelinearize(divisor, 1, 256, 129)
    #d = cc.EvalBootstrap(d)
    h = cc.EvalMult(h,d)
    #h = cc.EvalBootstrap(h)

    return h


def subtracao(h1, h2, coef):
    g = cc.EvalMultAndRelinearize(h2, coef)
    #g = cc.EvalBootstrap(g)
    h1 = cc.EvalSub(h1, g)
    #h1 = cc.EvalBootstrap(h1)

    return h1

def gauss(matrix, b, M):
    for i in range(M):
        # #print("noise budget before", matrix[i].GetNoiseScaleDeg(), i)
        #print("m[i]", i, decrypt(matrix[i],keys.secretKey))
        #print("m[i][i]", i, decrypt(getCipherTextAtSlot(matrix[i], i),keys.secretKey))
        print(i, decrypt(matrix[i], keys.secretKey))
        d = cc.EvalDivide(getCipherTextAtSlot(matrix[i], i), 1, 256, 129)
        print("(d)",i,  decrypt(d, keys.secretKey))

        #print("before (m[i])",i,  decrypt(matrix[i], keys.secretKey))
        matrix[i] = cc.EvalMultAndRelinearize(matrix[i],d)
        matrix[i] = cc.EvalBootstrap(matrix[i])
        print(i, decrypt(matrix[i], keys.secretKey))

        #print("noise budget after", matrix[i].GetNoiseScaleDeg(), i)
        #print("iteration ", i)
        for j in range(M):
            if (i != j):
                # b[j] -= b[i] * matrix[j][i]
                # p = cc.EvalMult(b, getCipherTextAtSlot(matrix[j], i))
                # p = cc.EvalBootstrap(p)
                # b[j] = cc.EvalSub(b[j], p)
                # b[j] = cc.EvalBootstrap(b[j])
                # b[j] = cc.EvalBootstrap(b[j])
                #print("noise budget before", matrix[i].GetNoiseScaleDeg(), j)
                #print("(m[j])", j, decrypt(matrix[j], keys.secretKey))
                #print("(m[j][i])", j, decrypt(getCipherTextAtSlot(matrix[j], i), keys.secretKey))
                print(i, j,  decrypt(matrix[j], keys.secretKey))
                g = cc.EvalMultAndRelinearize(matrix[i], getCipherTextAtSlot(matrix[j], i))
                matrix[j] = cc.EvalSub(matrix[j], g)
                matrix[j] = cc.EvalBootstrap(matrix[j])
                print(i, j,  decrypt(matrix[j], keys.secretKey))

                #print("noise budget after", matrix[i].GetNoiseScaleDeg(), j)
                #matrix[j] = cc.ReEncrypt(matrix[j])

    return b

gauss(encrypted_A, encrypted_B, len(encrypted_A))

#print(f"Number of levels remaining: {depth - encrypted_A[0][0].GetLevel()}")

############

decrypted_A = []
decrypted_B = []

for i in range(len(b_exemplo)):
    decrypted_A.append(decrypt(encrypted_A[i], keys.secretKey))
    #print(i)
    #decrypted_B.append(decrypt(encrypted_B[i], keys.secretKey))
    # for j in range(len(b_exemplo)):
    #decrypted_A[i].append(decrypt(encrypted_A[i][j], keys.secretKey))


print(decrypted_A)
#print(decrypted_B)
# result = cc.Decrypt(c_add,keys.secretKey)
# result.SetLength(batch_size)
# print("c1 + c2 = " + str(result))









