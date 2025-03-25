# Symmetric and Asymmetric Encryption

Basic Encryption/Decryption Application (Easy)

Technologies: Java, AES, RSA

Description:
	•	Develop a simple Java application that can encrypt and decrypt text using AES for symmetric encryption and RSA for asymmetric encryption.
	•	Allow users to input text and choose the encryption method.
	•	Include a basic user interface (CLI or GUI).

## Understanding AES and RSA

### AES (Advanced Encryption Standard): 

* **Overview:** This is a symmetric encryption algorithm, meaning the same key is used for both encryption and decryption

* It's widely used to secure data in a variety of applications, from encrypting files and communications to securing web traffic (e.g. HTTPS)

* **Key Features of AES:**

	* **Key Lengths:** AES works with fixed key sizes of 128, 192, or 256 bits

		* AES-128 uses a 128-bit key (16 bytes).
		* AES-192 uses a 192-bit key (24 bytes).
		* AES-256 uses a 256-bit key (32 bytes).

	* **Block Cypher:** AES operates on fixed-size blocks of data (128 bits or 16 bytes). If the data to be encrypted is larger than 128 bits, it is split into multiple blocks and each block is encrypted separately

	* **Rounds:** AES uses a series of transformations (called "rounds") to encrypt data.

		* AES-128: 10 rounds
		* AES-192: 12 rounds
		* AES-256: 14 rounds

	* **Encryption Process:**

		* **Key Expansion:** The original encryption key is expanded into multiple round keys.
		* **Rounds:** The encryption process applies th 10,12 or 14 rounds based on the key size.
		* **Final Round:** The final round doesn't involve the MixColumns step, but the other steps are the same

* **AES Security:**

	* AES is considered very secure when used with sufficiently long keys (e.g. AES-256).
	* The security of AES is mainly dependent on the strength of the key and how securely the key is stored.
	* AES-128 is vulnerable to brute-force attacks but would take an infeasible amount of time to break with current technology

* **AES Example:**

	* You want to encrypt a piece of data using a key. The data is divided into 128-bit blocks, and the key is applied to each block through multiple rounds. The result is a ciphertext that can only be decrypted using the same key.

### RSA (Rivest-Shamir-Adleman): 

* **Overview:** This is an asymmetric encryption algorithm that uses a pair of keys (public and private)

* **Key Features of RSA:**

	* **Key Pair:** RSA relies on a key pair:
		* **Public Key:** This key is shared openly and is used to encrypt data.
		* **Private Key:** This key is kept secret and is used to decrypt data encrypted with the corresponding public key.

	* **Encryption and Decryption:**
		* Data encrypted with the public key can only be decrypted by the private key
		* Conversely, data encrypted with the **private key** can only be decrypted with the **public key** (though this is less common, it's used in digital signatures).

	* **Mathematics Behind RSA:** RSA is based on the difficulty of factoring large prime numbers. It uses the following steps:

		* **Key Generation:**
			* Select two large prime numbers, `p` and `q`
			* Compute `n = p * q`, which is used as part of both the public and private keys
			* Calculate Euler's totient function, `φ(n) = (p - 1) * (q - 1)`.
			* Choose an encryption exponent `e` such that `1 < e < φ(n)` and e is coprime with `φ(n)`.
			* Calculate the decryption exponent `d` such that `d ≡ e⁻¹ (mod φ(n))`. This is the modular inverse of `e` modulo `φ(n)`.
		* **Public Key:** `(n,e)`
		* **Private Key:** `(n,d)`

	* **Encryption and Decryption:**

		* **Encryption:** `ciphertext = plaintext^e mod n`
		* **Decryption:** `ciphertext = plaintext^d mod n`

* **RSA Security:**

	* The security of RSA relies on the fact that factoring large numbers (specifically, the product of two large prime numbers `n = p * q`) is computationally difficult.
	* The strength of RSA is determined by the size of the modulus `n`. A typical RSA key size is at least 2048 bits.
	* If the private key is kept secure and the key pair is large enough (2048 bits or more), RSA is considered very secure. 

* **RSA Example:**

	* You want to send a secure message to someone.
	* You obtain their **public key** and encrypt your message using it
	* They use their **private key** to decrypt the message and read it
	* If they send a message back, they will encrypt it using your **public key**, and only you can decrypt it using your **private key**

### Key Differences Between AES and RSA:

| Feature             | AES (Symmetric)                           | RSA (Asymmetric)                        |
|---------------------|-------------------------------------------|----------------------------------------|
| **Key Type**        | Single key for both encryption and decryption. | Two keys: public key for encryption, private key for decryption. |
| **Encryption Speed**| Faster due to smaller key sizes and simpler operations. | Slower due to complex mathematical operations. |
| **Use Case**        | Ideal for encrypting large volumes of data. | Ideal for secure key exchange and digital signatures. |
| **Security**        | Security depends on the key length (e.g., AES-256 is highly secure). | Security depends on the difficulty of factoring large primes. |
| **Key Management**  | Requires secure handling of the secret key. | Public key can be freely shared; private key must be kept secure. |

* **Summary:**

	* **AES** is fast and suitable for encrypting large amounts of data, but it requires securely managing the key. It's symmetric encryption, meaning both encryption and decryption use the same key.
	
	* **ESA** is slower but allows secure communication without needing to share a secret key. It's asymmetric encryption, using a public and a private key

	## Exercise Log

	* **2025-03-19 - Learning AES in Java**
		* Will follow this guide for AES part of project: [Java AES Encryption and Decryption](https://www.baeldung.com/java-aes-encryption-decryption)
		* Using Java Cryptography Architecture (JCA) within the JDK
		* Tutorial will use **AES/CBC/PKCS5Padding** algorithm
		* For AES we need three params:
			* Input Data > String, File, Object...
			* Secret Key
				* Generate from random num or deriving from given password
				* In the first approach key needs to ben gen from a Crypto Secure Random num gen like [`SecureRandom`](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/SecureRandom.html) class
				* For generating a SecretKey we can use the [`KeyGenerator`](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/KeyGenerator.html) class
			* IV
		* ECB > Cannot be used because it always outputs the same thing, so it's easy to decipher the ciphertext
		* CBC (Will be used)
			* Uses IV to overcome ECB weakness 
			* Encryption cannot be parallelized. Decryption can (Interesting property)
			* Requires padding (fill up the 128 bits)
			* Size of data after encryption
				* `cleartext_size + (16 - (cleartext_size % 16))`
				* This quick equation basically represents the fact that AES always needs to be in 128 bits blocks, so if text doesn't fit, and you use padding, you can get an additional size, so encrypting the letter `a` which would be 1 byte, will actually create a ciphertext of 128 bits (TODO: Experiment this later)
		* Secret Key
			* Generate key from a random number
				* Using `KeyGenerator` class, as in example from tutorial which internally uses `SecureRandom` since `Random` class could be deterministic if using the same seed
			* Generate key from password-based key derivation function
				* like `PBKDF2`
				* We also need a salt value for turning a password into a secret key
				* We'll use the `SecretKeyFactory` class with the `PBKDF2WithHmacSHA256` algorithm for generating a key from a given password
		* IV
			* Pseudo-random value used to ensure that the same plaintext encrypted with same key produces different ciphertexts
			* Tipically 12 bytes
			* iv > byte array with random numbers

		* Base64 Encoding and Decoding
			* [Based on this article](https://www.baeldung.com/java-base64-encode-and-decode)
			* When you encrypt it will be in byte[] format, Base64 is the proper way to transmit the message via HTTP
		
	* **2025-03-24 - Learning RSA in Java**
		* Will follow this guide for RSA part of project: [RSA in Java](https://www.baeldung.com/java-rsa)
		* Key Pair
			* Use `KeyPairGenerator` from `java.security`
			* Will generate a `KeyPair` which also generates `PrivateKey` and `PublicKey`
			* Can store Key in a file in its encoded format then read it to bytes again

	## Exercises Final Results

	* AES
		* Code for AES is in [AESUtils.java](utils/AESUtils.java)
		* Execution of code is in [AESUtilsTest.java](../../../../../../../test/java/com/mccarthydev/crypto/Criptography/SymmetricAssymetricEncryption/utils/AESUtilsTest.java)
	* RSA
		* Code for RSA is in [RSAUtils.java](utils/RSAUtils.java)
		* Execution of code is in [RSAUtilsTest.java](../../../../../../../test/java/com/mccarthydev/crypto/Criptography/SymmetricAssymetricEncryption/utils/RSAUtilsTest.java)


		
