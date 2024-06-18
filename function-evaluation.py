from openfhe import *
import math

def main():
    eval_division_example()

def eval_logistic_example():
    print("--------------------------------- EVAL LOGISTIC FUNCTION ---------------------------------\n")
    parameters = CCParamsCKKSRNS()
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 10)

    scaling_mod_size = 59
    first_mod_size = 60

    parameters.SetScalingModSize(scaling_mod_size)
    parameters.SetFirstModSize(first_mod_size)

    poly_degree = 16
    mult_depth = 6

    parameters.SetMultiplicativeDepth(mult_depth)
    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)

    key_pair = cc.KeyGen()
    cc.EvalMultKeyGen(key_pair.secretKey)

    input = [-4, -3, -2, -1, 0, 1, 2, 3, 4]
    encoded_length = len(input)
    plaintext = cc.MakeCKKSPackedPlaintext(input)
    ciphertext = cc.Encrypt(key_pair.publicKey, plaintext)

    lower_bound = -4
    upper_bound = 4
    result = cc.EvalLogistic(ciphertext, lower_bound, upper_bound, poly_degree)

    plaintext_dec = cc.Decrypt(result, key_pair.secretKey)
    plaintext_dec.SetLength(encoded_length)

    expected_output = [0.0179885, 0.0474289, 0.119205, 0.268936, 0.5, 0.731064, 0.880795, 0.952571, 0.982011]
    print(f"Expected output\n\t {expected_output}\n")

    final_result = plaintext_dec.GetCKKSPackedValue()
    print(f"Actual output\n\t {final_result}\n")

def eval_division_example():
    print("--------------------------------- EVAL SQUARE ROOT FUNCTION ---------------------------------\n")
    parameters = CCParamsCKKSRNS()
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 8)

    if get_native_int() == 128:
        scaling_mod_size = 78
        first_mod_size = 89
    else:
        scaling_mod_size = 50
        first_mod_size = 60

    parameters.SetScalingModSize(scaling_mod_size)
    parameters.SetFirstModSize(first_mod_size)

    mult_depth = 12

    parameters.SetMultiplicativeDepth(mult_depth)
    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)

    key_pair = cc.KeyGen()
    cc.EvalMultKeyGen(key_pair.secretKey)

    input = [2, 3 ,4 ,5, 6, 7]
    i = 5
    encoded_length = len(input)
    plaintext = cc.MakeCKKSPackedPlaintext(input)
    ciphertext = cc.Encrypt(key_pair.publicKey, plaintext)
    cc.EvalRotateKeyGen(key_pair.secretKey, list(range(-(encoded_length + 1), encoded_length+ 1)))

    result_ = ciphertext # 1 / 2

    # executing hereee

    mask = [0] * encoded_length
    mask[i] = 1

    mask_ciphertext = cc.Encrypt(key_pair.publicKey, cc.MakeCKKSPackedPlaintext(mask))
    result = cc.EvalMult(result_, mask_ciphertext)

    result = cc.EvalRotate(result, i)
    r_merge = [result] * encoded_length

    print(r_merge)
    result = cc.EvalMerge(r_merge)

    plaintext_dec = cc.Decrypt(result, key_pair.secretKey)
    plaintext_dec.SetLength(encoded_length)

    final_result = plaintext_dec.GetRealPackedValue()
    print(f"Actual output\n\t {final_result}\n")

def getI(ciphertext, size,  i):
    mask = [0] * encoded_length
    mask[i] = 1

    mask_ciphertext = cc.Encrypt(key_pair.publicKey, cc.MakeCKKSPackedPlaintext(mask))
    result = cc.EvalMult(result_, mask_ciphertext)

    result = cc.EvalRotate(result, i)
    r_merge = [result] * encoded_length

    print(r_merge)
    result = cc.EvalMerge(r_merge)


    return result




if __name__ == "__main__":
    main()