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
        # print(i, matrix[i])
        matrix[i] = divisao_linha(matrix[i], matrix[i][i], M) 
        # print(i, matrix[i])
        for j in range(M):
            if (i != j):
                b[j] -= b[i] * matrix[j][i]
                # print(i, j, matrix[j])
                matrix[j] = subtracao(matrix[j], matrix[i], matrix[j][i], M)
                # print(i, j, matrix[j])
    return b
        
matriz_exemplo = [[1.9, 1.6, 1.8], [1.2, 1.9, 1.6], [1.1, 1.2, 1.9]]
b_exemplo = [1.3, 1.2, 1.7]


gauss(matriz_exemplo, b_exemplo, len(b_exemplo))
print(matriz_exemplo)
