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
        matrix[i] = divisao_linha(matrix[i], matrix[i][i], M)
        for j in range(M):
            if (i != j):
                b[j] -= b[i] * matrix[j][i]
                matrix[j] = subtracao(matrix[j], matrix[i], matrix[j][i], M)
    return b
        

matriz_exemplo = [[3, -0.1, -0.2], [0.1, 7, -0.3], [0.3, -0.2, 0]]
b_exemplo = [7.85, -19.3, 71.4]


print(gauss(matriz_exemplo, b_exemplo, 3))
