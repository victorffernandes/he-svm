using LinearAlgebra

function gauss_seidel(A::Matrix{Float64}, b::Vector{Float64}, x0::Vector{Float64}, tol::Float64, max_iter::Int)
    n = length(b)
    x = copy(x0)
    
    for iter in 1:max_iter
        x_old = copy(x)
        
        for i in 1:n
            sum = 0.0
            for j in 1:i-1
                sum += A[i,j] * x[j]
            end
            for j in i+1:n
                sum += A[i,j] * x_old[j]
            end
            x[i] = (b[i] - sum) / A[i,i]
        end
        
        # Check for convergence
        if norm(x - x_old, Inf) < tol
            return x, iter
        end
    end
    
    return x, max_iter
end

# Example usage
A = [2.0 1.0 -1.0; 2.0 -1.0 2.0; -2.0 1.0 2.0]
b = [8.0; -11.0; -3.0]
x0 = zeros(Float64, 3)
tol = 1e-6
max_iter = 100

solution, iterations = gauss_seidel(A, b, x0, tol, max_iter)
println("Solution: ", solution)
println("Iterations: ", iterations)