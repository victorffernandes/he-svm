from openfhe import *

mult_depth = 6
scale_mod_size = 50
batch_size = 4

parameters = CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(mult_depth)
parameters.SetScalingModSize(scale_mod_size)
parameters.SetBatchSize(batch_size)

cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)
cc.Enable(PKESchemeFeature.ADVANCEDSHE)

print("The CKKS scheme is using ring dimension: " + str(cc.GetRingDimension()))
num_slots = 4

keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)
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

    return result

def updateB(b, line, i, j):
    cb = getCipherTextAtSlot(b, i)# [b[i], b[i], ..., b[i]]
    cline = getCipherTextAtSlot(line, i) # [line[i], line[i], ..., line[i]]

    r = cc.EvalMultAndRelinearize(cb, cline)# [b[i] * line[i], b[i] * line[i], ..., b[i] * line[i]]

    mask = [0] * num_slots
    mask[j] = 1

    mask_ciphertext = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(mask)) # [0, 0, ..., 1, 0, 0] na posição j
    result_at_j = cc.EvalMultAndRelinearize(r, mask_ciphertext) # [0, 0, ..., b[i] * line[i], 0, 0] na posição j

    return cc.EvalSub(b, result_at_j) # b - [b[i], b[i], ..., b[i] * line[i], b[i], b[i]] na posição j


x1 = [0.25, 0.5, 0.75, 1.0]
x2 = [5.0, 4.0, 3.0, 2.0]

# 1.25

ptx1 = cc.MakeCKKSPackedPlaintext(x1)
ptx2 = cc.MakeCKKSPackedPlaintext(x2)

print("Input x1: " + str(ptx1))
print("Input x2: " + str(ptx2))

# Encrypt the encoded vectors
c1 = cc.Encrypt(keys.publicKey, ptx1)
c2 = cc.Encrypt(keys.publicKey, ptx2)

d = updateB(c1, c2, 0, 2)

result = cc.Decrypt(d, keys.secretKey)
result.SetLength(batch_size)
print("d = " + str(result.GetRealPackedValue()))
print("Estimated precision in bits: " + str(result.GetLogPrecision()))








