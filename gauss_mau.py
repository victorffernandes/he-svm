#-------- Método de Gauss -----------
def divisao_linha(h, divisor, m):
    for i in range(m):
        h[i] = h[i]/ divisor
    return h


def subtracao(h1, h2, coef, m):
    for i in range(m):
        h1[i] -= (h2[i] * coef)

    return h1

def gauss(matrix, b, M):

    for i in range(M):
        b[i] = b[i] / matrix[i][i]
        matrix[i] = divisao_linha(matrix[i], matrix[i][i], M)
        for j in range(M):
            if (i != j):
                b[j] -= b[i] * matrix[j][i]
                matrix[j] = subtracao(matrix[j], matrix[i], matrix[j][i], M)
    return b

#-----------------------------------------------------------------------


matriz_exemplo = [[2, 1, -1], [2, 1, 2], [-2, 1, 2]]
b_exemplo = [8, -11, -3]



print(gauss(matriz_exemplo, b_exemplo, 3))
