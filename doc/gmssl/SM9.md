# SM9

Given pairing e: G1 * G2 => GT, #G1 = #G2 = #GT = N, N is a prime.
P1 is the generate of G1, P2 is the generator of G2.

 * cid is the curve type, supersingular or non-supersingular.
 * eid is the pairing type, Weil, Tate, Ate or R-Ate.
 * Hv is a cryptographic hash function such as SHA-256 or SM3.
 * H1, H2 are two different HashToRange functions
 * hid is the id of H1 or H2

## System Setup

 1. Generate random number ks in [1, N - 1]
 2. Compute Ppub = ks * P2

Public parameters is Ppub, master secret is ks.

## Private key extraction

Given user identity ID

 1. Compute t1 = H1(ID||hid, N) + ks. If t1 == 0 then return "Failed"
 2. Compute t2 = ks * t1^{-1} mod N
 3. Compute ds = [t2]P1


## SM9 Signature Scheme

Given public parameters Ppub, message M and private key ds, the signature is
generate as follows:

 1. Compute g = e(P1, Ppub)
 2. Select random r in [1, N - 1]
 3. Compute w = g^r
 4. Compute h = H2(M||w, N)
 5. Compute l = (r - h) mod N, if l = 0, goto step 2.
 6. Compute S = [l]ds
 7. Output signature (h, S)

Given public parameters Ppub, message M and signer id ID

 1. Check if h is not in [1, N - 1] then return "Failed"
 2. Check if S is not in G1 then return "Failed" 
 3. Compute g = e(P1, Ppub), g in GT
 4. Compute t = g^h, t in GT
 5. Compute h1 = H1(ID||hid, N)
 6. Compute P = [h1]P2 + Ppub in group G2
 7. Compute u = e(S, P), u in GT
 8. Compute w = u * t, w in GT
 9. Compute h2 = H2(M||w, N). If h2 == h, return "Success", else return "Failed"



## SM9 Key Encapsulate

 1. Compute Q = [H1(ID||hid, N)]P1 + Ppub, Q in G1
 2. Generate random r in [1, N - 1]
 3. Compute C = [r]Q in G1
 4. COmpute g = e(Ppub, P2) in GT
 5. Compute w = g^r in GT
 6. Compute K = KDF(C||w||ID, klen), if K is all zero goto step 2.
 7. Output (K, C)

Decapsulate:

 1. Check if C in G1, else return "Failed"
 2. Compute w = e(C, d) in GT
 3. Compute K = KDF(C||w||ID, klen)
 4. Output K

## SM9 Encryption

 1. Compute Q = [H1(ID||hid, N)]P1 + Ppub in G1
 2. Generate random r in [1, N - 1]
 3. Compute C = [r]Q in G1
 4. COmpute g = e(Ppub, P2) in GT
 5. Compute w = g^r in GT
 6. If use KDF
	klen = mlen + len(K2)
	K = KDF(C1||w||ID, klen)
	K1 = K[0..mlen]
	K2 = K[mlen..]
	C2 = M xor K1

    else use ENC

	klen = len(K1) + len(K2)
	K = KDF(C1||w||ID, klen)
	K1 = K[0..len(K1)]
	K2 = K[len(K1)]
	C2 = Enc(K1, M)

 7. Compute C3 = MAC(K2, C2)
 8. Output (C1, C2, C3)





