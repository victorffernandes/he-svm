from openfhe import *

mult_depth = 6
scale_mod_size = 50
batch_size = 1

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

keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)
cc.EvalRotateKeyGen(keys.secretKey, [1, -2])

x1 = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]
x2 = [5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25]

ptx1 = cc.MakeCKKSPackedPlaintext([0.9])
ptx2 = cc.MakeCKKSPackedPlaintext([14.0])

print("Input x1: " + str(ptx1))
print("Input x2: " + str(ptx2))

# Encrypt the encoded vectors
c1 = cc.Encrypt(keys.publicKey, ptx1)
c2 = cc.Encrypt(keys.publicKey, ptx2)

# Step 4: Evaluation

d = cc.EvalDivide( c1, -1,2,2)

#d = cc.EvalDivide(d, -0.5,0.5,5)

# Homomorphic subtraction
c_sub = cc.EvalSub(c1, d)
# Homomorphic scalar multiplication
c_scalar = cc.EvalMult(c1,4)
# Homomorphic multiplication
c_mult = cc.EvalMult(c1, c2)
# Homomorphic rotations
c_rot1 = cc.EvalRotate(c1, 1)
c_rot2 = cc.EvalRotate(c1, -2)

# Step 5: Decryption and output
# Decrypt the result of additions
#ptAdd = cc.Decrypt(c_add,keys.secretKey)

# We set the precision to 8 decimal digits for a nicer output.
# If you want to see the error/noise introduced by CKKS, bump it up
# to 15 and it should become visible.

result = cc.Decrypt(d, keys.secretKey)
result.SetLength(batch_size)
print("d = " + str(result.GetCKKSPackedValue()[0].real))
print("Estimated precision in bits: " + str(result.GetLogPrecision()))








