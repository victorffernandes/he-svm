def divisao_linha(h, divisor):
    """Divide uma linha da matriz pelo divisor"""
    return [elemento / divisor for elemento in h]

def subtracao(h1, h2, coef):
    """Subtrai uma linha da matriz multiplicada por um coeficiente de outra linha"""
    return [elem1 - coef * elem2 for elem1, elem2 in zip(h1, h2)]

def gauss(A, b):
    """Aplica o algoritmo de eliminação de Gauss na matriz A e no vetor b"""
    n = len(A)
    
    # Aplicar eliminação de Gauss
    for i in range(n):
        # Dividir a linha i pelo elemento A[i][i]
        divisor = A[i][i]
        A[i] = divisao_linha(A[i], divisor)
        b[i] /= divisor

        print(b)
        
        # Subtrair a linha i das outras linhas
        for j in range(n):
            if i != j:
                coef = A[j][i]
                A[j] = subtracao(A[j], A[i], coef)
                b[j] -= coef * b[i]
    
    return b
        
matriz_exemplo = [[0 , 1.6, 1.8], [1, 1.9 , 1.6], [1, 1.2, 1.9 ]]
b_exemplo = [0 , 5, 1.7]


print(gauss(matriz_exemplo, b_exemplo))
