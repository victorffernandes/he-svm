from openfhe import *
import matplotlib.pyplot as plt
import numpy as np
import math
from sklearn import datasets
from sklearn.preprocessing import StandardScaler

parameters = CCParamsCKKSRNS()
secret_key_dist = SecretKeyDist.UNIFORM_TERNARY
parameters.SetSecretKeyDist(secret_key_dist)

parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
parameters.SetRingDim(1<<10)

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

parameters = CCParamsCKKSRNS()
secret_key_dist = SecretKeyDist.UNIFORM_TERNARY
parameters.SetSecretKeyDist(secret_key_dist)

parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
parameters.SetRingDim(1<<10)

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
            print("tamo rodando ", j)
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
            print("E ", j)
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

#  --------------- IRIS PROCESSING ---------------

iris = datasets.load_iris()

def toLine(a):
    if(a == 0): 
        return -1
    return 1

applyAll = np.vectorize(toLine)

scaler = StandardScaler()

data = [*iris.data[:4, :2] , *iris.data[146:150, :2]]
X = np.array(data)

X = scaler.fit_transform(X)

data_y = [*iris.target[:4], *iris.target[146:150]]
y = np.array(applyAll(data_y))

#  --------------- ENCRYPTED SVM PROCESSING ---------------

def SVM(K, fi, M, y):
  identity = np.matrix(np.identity(M, dtype=int))

  val = K + ((1/fi)) * identity

  y_ = y.reshape((M, 1))
  resY = y_

  resY_ = []
  val_ = val.tolist()

  for h in resY:
    resY_.append(h[0])

  res = exec(val_, resY_, keys)

  return res

x = X
K = []

def k(x0, x1):
  return np.dot(np.array(x0), np.array(x1))

for i in range(0, len(x)):
  K.append([])
  for j in range(0, len(x)):
    K[i].append(k(x[i], x[j]))

K_train = np.matrix(K)
Y_train = y

r = SVM(K_train,30,len(x),Y_train)

#  --------------- SELECT BEST W ---------------

w_compare = [  2.28565, -2.57106] # best matching
slope_compare = -w_compare[0]/w_compare[1]

result = []

for i in range(len(y)):
    for j in range(len(y)):
        if len(result) == 0:
            result = [r[i],r[j]]
        if abs(slope_compare-(-r[i]/r[j])) < abs(slope_compare-(-result[0]/result[1])):
            result = [r[i],r[j]]
            print(result)
            print(-result[0]/result[1])
            print(i, j)
            

w = [result[0], result[1]]
b = 0.90926801
# b1 = 0

# --------------- PREDICT TEST ---------------

def lssvm_predict(X_test, alpha, b):
    y_pred = []
    for x in X_test:
      y_pred.append(-np.sign(np.dot(x, alpha) + b))
    return y_pred

X_test = np.array(iris.data[:, :2])

X_test = scaler.fit_transform(X_test)
y_test = np.array(applyAll(iris.target))

y_pred = lssvm_predict(X_test, w, b)

fp = 0
tp = 0
fn = 0
fp = 0
right = 0
wrong = 0

for i in range(len(y_pred)):
    if y_pred[i] == y_test[i]:
        if y_pred[i] == 1:
            tp += 1
        else:
            fp += 1
        right += 1
    else:
        if y_pred[i] == 1:
            fp += 1
        else:
            fn += 1
        wrong += 1

print(y_pred)
print("Right: ", right)
print("Wrong: ", wrong)
print("Precisão: ", tp/(tp+fp))
print("Acurácia: ", right/(len(y_pred)))
print("Recall: ", tp/(tp + fn))

# --------------- PLOT HYPERPLANE ---------------

fig, ax = plt.subplots(figsize=(8, 8))

slope = -w[0]/w[1]
intercept_ = -b/w[1]
ax.axline((0, intercept_), slope=slope, color='orange', linestyle='--', label='Decision Boundary')

# # Plot samples by color and add legend
scatter = ax.scatter(X_test[:, 0], X_test[:, 1], s=20, c=y_test, label=y, edgecolors="k")
ax.legend(*scatter.legend_elements(), loc="upper right", title="Classes")
ax.set_title("Samples in two-dimensional feature space")
_ = plt.show()




