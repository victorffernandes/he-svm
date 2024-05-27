# Define the function for Gaussian elimination
function gauss_elimination!(A::Matrix{Float64}, b::Vector{Float64})
    n = length(b)
    
    # Forward elimination
    for k in 1:n-1
        println("Matriz atual: ", A)  
        for i in k+1:n
            if A[i,k] != 0.0
                factor = A[i,k] / A[k,k]
                for j in k:n
                    A[i,j] -= factor * A[k,j]
                end
                b[i] -= factor * b[k]
            end
        end
    end
    
    # Back substitution
    x = zeros(Float64, n)
    for i in n:-1:1
        sum = 0.0
        for j in i+1:n
            sum += A[i,j] * x[j]
        end
        x[i] = (b[i] - sum) / A[i,i]
    end
    
    return x
end

# Example usage
A = [2.0 1.0 -1.0; 0 -1.0 2.0; 0 0 2.0]

b = [8.0; -11.0; -3.0]

x = gauss_elimination!(copy(A), copy(b))
println("Solution: ", x)