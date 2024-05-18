using LinearAlgebra

function jacobi(A::Matrix{Float64}, b::Vector{Float64}, x0::Vector{Float64}, tol::Float64, max_iter::Int)
    n = length(b)
    x = copy(x0)
    x_new = zeros(Float64, n)
    
    for iter in 1:max_iter
        for i in 1:n
            sum = 0.0
            for j in 1:n
                if i != j
                    sum += A[i,j] * x[j]
                end
            end
            x_new[i] = (b[i] - sum) / A[i,i]
        end
        
        if norm(x_new - x, Inf) < tol
            println("robson")
            return x_new, iter
        end
        
        x = copy(x_new)
    end
    
    return x_new, max_iter
end

# Example usage
A = [2.0 1.0 -1.0; 2.0 -1.0 2.0; -2.0 1.0 2.0]
b = [8.0; -11.0; -3.0]
x0 = zeros(Float64, 3)
tol = 1e-6
max_iter = 3000

solution, iterations = jacobi(A, b, x0, tol, max_iter)
println("Solution: ", solution)
println("Iterations: ", iterations)