from openfhe import *

parameters = CCParamsCKKSRNS()
secret_key_dist = SecretKeyDist.UNIFORM_TERNARY
parameters.SetSecretKeyDist(secret_key_dist)

parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
parameters.SetRingDim(1<<8)

rescale_tech = ScalingTechnique.FLEXIBLEAUTO
dcrt_bits = 50
first_mod = 60

parameters.SetScalingModSize(dcrt_bits)
parameters.SetScalingTechnique(rescale_tech)
parameters.SetFirstModSize(first_mod)

level_budget = [4, 4]

levels_available_after_bootstrap = 40
depth = levels_available_after_bootstrap + FHECKKSRNS.GetBootstrapDepth(level_budget, secret_key_dist)

parameters.SetMultiplicativeDepth(depth)

cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)
cc.Enable(PKESchemeFeature.ADVANCEDSHE)
cc.Enable(PKESchemeFeature.FHE)

ring_dim = cc.GetRingDimension()

num_slots = int(ring_dim/2)

cc.EvalBootstrapSetup(level_budget, slots=num_slots)

keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)
cc.EvalBootstrapKeyGen(privateKey=keys.secretKey,  slots=num_slots)
cc.EvalRotateKeyGen(keys.secretKey, list(range(-(num_slots + 1), num_slots+ 1)))


def get_ciphertext_at(ciphertext,  i):
    mask = [0] * num_slots
    mask[i] = 1

    mask_ciphertext = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(mask))
    result = cc.EvalMultAndRelinearize(ciphertext, mask_ciphertext)

    if i != 0:
        result = cc.EvalRotate(result, i)
    r_merge = [result] * num_slots

    result = cc.EvalMerge(r_merge)

    return result


def decrypt(a, sk, length):
    result = cc.Decrypt(a,sk)
    #print(result)
    result.SetLength(length)
    return  result.GetRealPackedValue()

def sub_at_index(b, r, j):
    mask = [0] * num_slots
    mask[j] = 1

    mask_ciphertext = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(mask))
    result_at_j = cc.EvalMultAndRelinearize(r, mask_ciphertext)

    return cc.EvalSub(b, result_at_j)
    
def divide_at_index(b, dividend, i):
    cb = get_ciphertext_at(b, i)

    r = cc.EvalMultAndRelinearize(cb, dividend)

    mask1 = [0] * num_slots
    mask1[i] = 1
    mask1_ciphertext = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(mask1))
    
    mask2 = [1] * num_slots
    mask2[i] = 0
    mask2_ciphertext = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(mask2))
    
    b_without_i = cc.EvalMultAndRelinearize(b, mask2_ciphertext) # [0, 0, ..., b[i] * line[i], 0, 0] na posição j
    r_with_i = cc.EvalMultAndRelinearize(r, mask1_ciphertext) # [0, 0, ..., b[i] * line[i], 0, 0] na posição j

    return cc.EvalAdd(b_without_i, r_with_i) # b - [b[i], b[i], ..., b[i] * line[i], b[i], b[i]] na posição j
    
def gauss(matrix, b, M):
    for i in range(M):
        d = cc.EvalDivide(get_ciphertext_at(matrix[i], i), 1, 256, 129)
        matrix[i] = cc.EvalMultAndRelinearize(matrix[i],d)
        matrix[i] = cc.EvalBootstrap(matrix[i])

        b = divide_at_index(b, d, i)
        b = cc.EvalBootstrap(b)

        for j in range(M):
            if (i != j):
                cb = get_ciphertext_at(b, i)
                cline = get_ciphertext_at(matrix[j], i)
                r = cc.EvalMultAndRelinearize(cb, cline)

                b = sub_at_index (b, r, j)
                g = cc.EvalMultAndRelinearize(matrix[i], get_ciphertext_at(matrix[j], i))
                matrix[j] = cc.EvalSub(matrix[j], g)
                matrix[j] = cc.EvalBootstrap(matrix[j])

    return b

def exec(K, b, keys):
    encoded_A = []
    encoded_B = cc.MakeCKKSPackedPlaintext(b)

    for i in range(len(b)):
        encoded_A.append(cc.MakeCKKSPackedPlaintext(K[i]))
        encoded_A[i].SetLength(num_slots)

    encrypted_A = []
    encrypted_B = cc.Encrypt(keys.publicKey, encoded_B)

    for i in range(len(b)):
        encrypted_A.append(cc.Encrypt(keys.publicKey, encoded_A[i]))

    result_b = gauss(encrypted_A, encrypted_B, len(b))

    return decrypt(result_b, keys.secretKey, len(b))

matriz_exemplo = [[1.9 , 1.6, 1.8], [1.2, 1.9 , 1.6], [1.1, 1.2, 1.9 ]]
b_exemplo = [1.3 , 5, 1.7]

print("B", exec(matriz_exemplo, b_exemplo, keys))










