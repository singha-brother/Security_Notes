import random 

primes = [	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
			101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
			211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
			307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
			401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499,
			503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599,
			601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691,
			701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
			809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887,
				907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997
		]
prime1, prime2 = random.sample(primes, 2)
product = prime1 * prime2  
totient = (prime1 - 1) * (prime2 - 1)

# Select Public key
is_choosing = True 
while is_choosing:
	public_key = random.choice(primes)
	if public_key < totient:
		is_choosing = False 
	if (totient % public_key != 0):
		is_choosing = False 

# calculating Private Key
is_calculating = True 
private_key = 1
while is_calculating:
	if (private_key * public_key) % totient == 1:
		is_calculating = False 
		break
	private_key += 1



print("===================================================")
print("======================= RSA =======================")
print("===================================================")
print("[1] Generating Keys")
print(f"[*] Select Two Primes, P & Q            - {prime1}, {prime2}")
print(f"[x] Product of Two Primes, (P x Q)      - {product}")
print(f"[x] Totient, (P - 1) x (Q - 1)          - {totient}")
print(f"[!] Selected Public Key, E              - {public_key}")
print(f"[!] Choosen Private Key, D              - {private_key}\n")
print("[2] Encryption / Decryption ")

message = int(input("[*] Enter Message, Integer :\n "))
cipher_text = (message ** public_key) % product
decrypted_msg = (cipher_text**private_key) % product


print(f"[x] Cipher Text, (M ^ E) MOD N          - {cipher_text}")
print(f"[x] Decrpyt Message, (Cipher ^ D) MOD N - {decrypted_msg}")
