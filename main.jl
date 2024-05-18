include("utils.jl")

using SEAL
using Printf


function main()
  parms = EncryptionParameters(SchemeType.ckks)

  poly_modulus_degree = 8192
  set_poly_modulus_degree!(parms, poly_modulus_degree)
  set_coeff_modulus!(parms, coeff_modulus_create(poly_modulus_degree, [60, 40, 40, 60]))

  initial_scale = 2.0^40

  context = SEALContext(parms)
  println()

  keygen = KeyGenerator(context)
  public_key_ = PublicKey()
  create_public_key!(public_key_, keygen)
  secret_key_ = secret_key(keygen)
  relin_keys_ = RelinKeys()
  create_relin_keys!(relin_keys_, keygen)
  encryptor = Encryptor(context, public_key_)
  evaluator = Evaluator(context)
  decryptor = Decryptor(context, secret_key_)


  # podemos criptografar vetores de até 4096 posições
  encoder = CKKSEncoder(context)
  slot_count_ = slot_count(encoder)
  println("Number of slots: ", slot_count_)

  n = 10
  M = Array{Float64}(undef, n, n)
  for i in 1:n
    for j in 1:n
        M[i,j] = j + i
    end
  end

  M_c = Array{Any}(undef, n);

  for i in 1:n
    plain = Plaintext()
    encode!(plain, collect(M[i, :]), initial_scale, encoder)
    M_c[i] = Ciphertext()
    encrypt!(M_c[i], plain, encryptor)
  end

  for i in 1:n
    M_c[i] = Ciphertext()
    add!(M_c[i], M_c[i], M_c[i], evaluator)
  end

  M_plain = Array{Any}(undef, n);
  for i in 1:n
    M_plain[i] = Plaintext()
    decrypt!(M_plain[i], M_c[i], decryptor)
  end

  M_decoded = Array{Float64}(undef, 2 * n, 2 * n);
  for i in 1:n
    list_decoded = collect(Array{Float64}(undef, 2 * n));
    #println(typeof(list_decoded))
    decode!(list_decoded, M_plain[i], encoder)
    println("Linha decode ", i, list_decoded)
    #println(typeof(list_decoded))
    #M_decoded[i, :] = list_decoded 
  end

  #println("result: ", M_decoded)

  # # add!(x1_encrypted, x1_encrypted, x1_encrypted, evaluator);


  # # plain_result = Plaintext()
  # # print_line(@__LINE__)
  # # println("Decrypt and decode PI*x^3 + 0.4x + 1.")

  # # decrypt!(plain_result, x1_encrypted, decryptor)
  # #result = similar(input)
  # # decode!(result, plain_result, encoder)
  # # println("    + Computed result ...... Correct.")
  # # println(result)
end

main()