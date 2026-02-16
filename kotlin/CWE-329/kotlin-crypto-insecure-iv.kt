import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.Base64

// True Positive Examples (Insecure/Vulnerable Code)

// {fact rule=static-initialization-vector@v1.0 defects=1}
fun bad_case_1() {
    // Using a hardcoded IV for AES encryption
    val key = SecretKeySpec("ThisIsASecretKey".toByteArray(), "AES")
    val hardcodedIv = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    // ruleid: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(hardcodedIv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Sensitive data".toByteArray())
    println(Base64.getEncoder().encodeToString(encrypted))
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=1}
fun bad_case_2() {
    // Using a static, predictable IV
    val key = KeyGenerator.getInstance("AES").generateKey()
    val staticIv = "1234567890123456".toByteArray()
    
    // ruleid: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(staticIv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Secret message".toByteArray())
    println(Base64.getEncoder().encodeToString(encrypted))
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=1}
fun bad_case_3() {
    // Reusing the same IV for multiple encryptions
    val key = SecretKeySpec("AnotherSecretKey1".toByteArray(), "AES")
    val reuseIv = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)
    
    // ruleid: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(reuseIv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    // First encryption
    val encrypted1 = cipher.doFinal("First message".toByteArray())
    
    // Reusing the same IV for second encryption
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    val encrypted2 = cipher.doFinal("Second message".toByteArray())
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=1}
fun bad_case_4() {
    // Using an IV with insufficient randomness
    val key = KeyGenerator.getInstance("AES").generateKey()
    val weakIv = ByteArray(16)
    val random = java.util.Random() // Not cryptographically secure
    random.nextBytes(weakIv)
    
    // ruleid: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(weakIv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Confidential data".toByteArray())
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=1}
fun bad_case_5() {
    // Using a constant string as IV
    val key = SecretKeySpec("ThisIsMySecretKey".toByteArray(), "AES")
    val constantIv = "ConstantIVString!".toByteArray()
    
    // ruleid: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(constantIv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Private information".toByteArray())
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=1}
fun bad_case_6() {
    // Using an IV derived from the encryption key
    val keyString = "SuperSecretKey123"
    val key = SecretKeySpec(keyString.toByteArray(), "AES")
    val keyDerivedIv = keyString.substring(0, 16).toByteArray()
    
    // ruleid: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(keyDerivedIv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Sensitive customer data".toByteArray())
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=1}
fun bad_case_7() {
    // Using a predictable pattern for IV
    val key = KeyGenerator.getInstance("AES").generateKey()
    val patternIv = ByteArray(16) { i -> i.toByte() } // [0, 1, 2, 3, ...]
    
    // ruleid: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(patternIv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Protected health information".toByteArray())
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=1}
fun bad_case_8() {
    // Using timestamp as IV (predictable)
    val key = SecretKeySpec("AnotherSecretKey2".toByteArray(), "AES")
    val timestamp = System.currentTimeMillis().toString()
    val timestampIv = timestamp.padEnd(16, '0').substring(0, 16).toByteArray()
    
    // ruleid: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(timestampIv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Financial transaction data".toByteArray())
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=1}
fun bad_case_9() {
    // Using all zeros as IV
    val key = KeyGenerator.getInstance("AES").generateKey()
    val zeroIv = ByteArray(16) // Default initialization to zeros
    
    // ruleid: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(zeroIv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("User credentials".toByteArray())
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=1}
fun bad_case_10() {
    // Using a counter as IV (predictable sequence)
    val key = SecretKeySpec("YetAnotherSecKey".toByteArray(), "AES")
    var counter = 0
    
    // Encryption function that uses a counter-based IV
    fun encryptWithCounter(data: String) {
        val counterBytes = counter.toString().padStart(16, '0').toByteArray()
        counter++
        
        // ruleid: kotlin-crypto-insecure-iv
        val ivSpec = IvParameterSpec(counterBytes)
        
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
        
        val encrypted = cipher.doFinal(data.toByteArray())
    }
    
    encryptWithCounter("Message 1")
    encryptWithCounter("Message 2")
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=1}
fun bad_case_11() {
    // Using user input as IV (potentially predictable or manipulable)
    val key = KeyGenerator.getInstance("AES").generateKey()
    val userProvidedIv = "UserInput123456789".substring(0, 16).toByteArray()
    
    // ruleid: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(userProvidedIv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Sensitive API response".toByteArray())
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=1}
fun bad_case_12() {
    // Using a fixed IV stored in a constant
    val key = SecretKeySpec("SecretAESKey1234".toByteArray(), "AES")
    val FIXED_IV = byteArrayOf(10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160)
    
    // ruleid: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(FIXED_IV)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Payment information".toByteArray())
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=1}
fun bad_case_13() {
    // Using an IV with insufficient length
    val key = KeyGenerator.getInstance("AES").generateKey()
    val shortIv = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8) // Only 8 bytes, AES needs 16
    val paddedIv = shortIv + shortIv // Duplicating to reach required length
    
    // ruleid: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(paddedIv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Personal identification data".toByteArray())
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=1}
fun bad_case_14() {
    // Using a static IV from a configuration file (simulated)
    val key = SecretKeySpec("ConfigSecretKey12".toByteArray(), "AES")
    
    // Simulating reading IV from a config
    val configIv = "ConfigIvValue1234".toByteArray()
    
    // ruleid: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(configIv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Authentication token".toByteArray())
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=1}
fun bad_case_15() {
    // Using a simple transformation of the key as IV
    val keyString = "MasterEncryptKey"
    val key = SecretKeySpec(keyString.toByteArray(), "AES")
    
    // Creating IV by reversing and modifying the key
    val transformedIv = keyString.reversed().toByteArray()
    
    // ruleid: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(transformedIv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Secure document content".toByteArray())
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=static-initialization-vector@v1.0 defects=0}
fun good_case_1() {
    // Using SecureRandom to generate a random IV
    val key = KeyGenerator.getInstance("AES").generateKey()
    val iv = ByteArray(16)
    val secureRandom = SecureRandom()
    secureRandom.nextBytes(iv)
    
    // ok: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(iv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Sensitive data".toByteArray())
    println(Base64.getEncoder().encodeToString(encrypted))
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=0}
fun good_case_2() {
    // Using SecureRandom with getInstance method
    val key = SecretKeySpec("ThisIsASecretKey".toByteArray(), "AES")
    val iv = ByteArray(16)
    val secureRandom = SecureRandom.getInstance("SHA1PRNG")
    secureRandom.nextBytes(iv)
    
    // ok: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(iv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Secret message".toByteArray())
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=0}
fun good_case_3() {
    // Generating a new IV for each encryption
    val key = KeyGenerator.getInstance("AES").generateKey()
    
    fun encryptData(data: String): ByteArray {
        val iv = ByteArray(16)
        SecureRandom().nextBytes(iv)
        
        // ok: kotlin-crypto-insecure-iv
        val ivSpec = IvParameterSpec(iv)
        
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
        
        return cipher.doFinal(data.toByteArray())
    }
    
    val encrypted1 = encryptData("First message")
    val encrypted2 = encryptData("Second message") // Different IV used
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=0}
fun good_case_4() {
    // Using Cipher's getIV method to retrieve the generated IV
    val key = SecretKeySpec("AnotherSecretKey".toByteArray(), "AES")
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    // ok: kotlin-crypto-insecure-iv
    cipher.init(Cipher.ENCRYPT_MODE, key) // Cipher generates a secure IV internally
    
    val iv = cipher.iv // Get the IV that was generated
    val encrypted = cipher.doFinal("Confidential data".toByteArray())
    
    // Store both IV and encrypted data for later decryption
    val ivAndEncrypted = iv + encrypted
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=0}
fun good_case_5() {
    // Storing the random IV with the ciphertext
    val key = KeyGenerator.getInstance("AES").generateKey()
    val iv = ByteArray(16)
    SecureRandom().nextBytes(iv)
    
    // ok: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(iv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Private information".toByteArray())
    
    // Prepend IV to the encrypted data for storage/transmission
    val combined = iv + encrypted
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=0}
fun good_case_6() {
    // Using a dedicated method to generate secure IVs
    val key = SecretKeySpec("SuperSecretKey123".toByteArray(), "AES")
    
    fun generateSecureIv(): ByteArray {
        val iv = ByteArray(16)
        SecureRandom().nextBytes(iv)
        return iv
    }
    
    val secureIv = generateSecureIv()
    
    // ok: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(secureIv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Sensitive customer data".toByteArray())
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=0}
fun good_case_7() {
    // Using GCM mode which handles IV generation securely
    val key = KeyGenerator.getInstance("AES").generateKey()
    
    // ok: kotlin-crypto-insecure-iv
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key)
    
    val iv = cipher.iv // GCM generates a secure IV
    val encrypted = cipher.doFinal("Protected health information".toByteArray())
    
    // Store IV with encrypted data
    val result = iv + encrypted
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=0}
fun good_case_8() {
    // Using a secure IV with proper error handling
    val key = SecretKeySpec("AnotherSecretKey2".toByteArray(), "AES")
    
    try {
        val iv = ByteArray(16)
        SecureRandom().nextBytes(iv)
        
        // ok: kotlin-crypto-insecure-iv
        val ivSpec = IvParameterSpec(iv)
        
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
        
        val encrypted = cipher.doFinal("Financial transaction data".toByteArray())
    } catch (e: Exception) {
        // Handle encryption errors
        println("Encryption failed: ${e.message}")
    }
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=0}
fun good_case_9() {
    // Using a cryptographically strong PRNG for IV generation
    val key = KeyGenerator.getInstance("AES").generateKey()
    val iv = ByteArray(16)
    
    // Using a named algorithm for stronger guarantees
    val strongRandom = SecureRandom.getInstance("SHA1PRNG")
    strongRandom.setSeed(SecureRandom().generateSeed(20)) // Additional entropy
    strongRandom.nextBytes(iv)
    
    // ok: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(iv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("User credentials".toByteArray())
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=0}
fun good_case_10() {
    // Encryption utility class with secure IV generation
    class SecureEncryptor(private val key: SecretKeySpec) {
        fun encrypt(data: String): Pair<ByteArray, ByteArray> {
            val iv = ByteArray(16)
            SecureRandom().nextBytes(iv)
            
            // ok: kotlin-crypto-insecure-iv
            val ivSpec = IvParameterSpec(iv)
            
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
            
            val encrypted = cipher.doFinal(data.toByteArray())
            return Pair(iv, encrypted)
        }
    }
    
    val encryptor = SecureEncryptor(SecretKeySpec("YetAnotherSecKey".toByteArray(), "AES"))
    val (iv, encrypted) = encryptor.encrypt("Message to encrypt")
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=0}
fun good_case_11() {
    // Using SecureRandom with additional entropy
    val key = KeyGenerator.getInstance("AES").generateKey()
    val secureRandom = SecureRandom()
    
    // Add additional entropy
    val additionalSeed = System.nanoTime().toString().toByteArray()
    secureRandom.setSeed(additionalSeed)
    
    val iv = ByteArray(16)
    secureRandom.nextBytes(iv)
    
    // ok: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(iv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Sensitive API response".toByteArray())
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=0}
fun good_case_12() {
    // Using a factory method to create secure encryption components
    class CryptoFactory {
        companion object {
            fun createSecureIv(): IvParameterSpec {
                val iv = ByteArray(16)
                SecureRandom().nextBytes(iv)
                return IvParameterSpec(iv)
            }
        }
    }
    
    val key = SecretKeySpec("SecretAESKey1234".toByteArray(), "AES")
    
    // ok: kotlin-crypto-insecure-iv
    val ivSpec = CryptoFactory.createSecureIv()
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Payment information".toByteArray())
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=0}
fun good_case_13() {
    // Using a secure IV with proper length validation
    val key = KeyGenerator.getInstance("AES").generateKey()
    
    fun createSecureIv(blockSize: Int): IvParameterSpec {
        if (blockSize <= 0) {
            throw IllegalArgumentException("Block size must be positive")
        }
        
        val iv = ByteArray(blockSize)
        SecureRandom().nextBytes(iv)
        return IvParameterSpec(iv)
    }
    
    // ok: kotlin-crypto-insecure-iv
    val ivSpec = createSecureIv(16) // AES block size
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Personal identification data".toByteArray())
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=0}
fun good_case_14() {
    // Using a secure IV with proper documentation
    val key = SecretKeySpec("ConfigSecretKey12".toByteArray(), "AES")
    
    // Generate a cryptographically secure random IV
    val secureRandom = SecureRandom.getInstanceStrong() // Most secure instance available
    val iv = ByteArray(16)
    secureRandom.nextBytes(iv)
    
    // ok: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(iv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Authentication token".toByteArray())
}
// {/fact}

// {fact rule=static-initialization-vector@v1.0 defects=0}
fun good_case_15() {
    // Using a secure IV with proper key management
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(256) // Use 256-bit keys for stronger security
    val key = keyGenerator.generateKey()
    
    val iv = ByteArray(16)
    SecureRandom().nextBytes(iv)
    
    // ok: kotlin-crypto-insecure-iv
    val ivSpec = IvParameterSpec(iv)
    
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    
    val encrypted = cipher.doFinal("Secure document content".toByteArray())
}
// {/fact}