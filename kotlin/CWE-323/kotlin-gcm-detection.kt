import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.Base64

// True Positive Examples (Vulnerable Code)

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=1}
fun bad_case_1() {
    // Using a fixed IV for GCM encryption
    val key = KeyGenerator.getInstance("AES").generateKey()
    val fixedIv = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    val plaintext1 = "Sensitive data 1".toByteArray()
    val cipher1 = Cipher.getInstance("AES/GCM/NoPadding")
    // ruleid: kotlin-gcm-detection
    cipher1.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, fixedIv))
    val ciphertext1 = cipher1.doFinal(plaintext1)
    
    val plaintext2 = "Sensitive data 2".toByteArray()
    val cipher2 = Cipher.getInstance("AES/GCM/NoPadding")
    // ruleid: kotlin-gcm-detection
    cipher2.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, fixedIv))
    val ciphertext2 = cipher2.doFinal(plaintext2)
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=1}
fun bad_case_2() {
    // Reusing the same IV for multiple encryptions
    val key = "0123456789abcdef".toByteArray()
    val secretKey = SecretKeySpec(key, "AES")
    val iv = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)
    val gcmSpec = GCMParameterSpec(128, iv)
    
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    // ruleid: kotlin-gcm-detection
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
    val encrypted1 = cipher.doFinal("First message".toByteArray())
    
    // Reusing the same IV for a second encryption
    // ruleid: kotlin-gcm-detection
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
    val encrypted2 = cipher.doFinal("Second message".toByteArray())
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=1}
fun bad_case_3() {
    // Using a static IV stored as a class member
    val staticIv = byteArrayOf(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
    val key = KeyGenerator.getInstance("AES").generateKey()
    
    fun encryptData(data: String): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // ruleid: kotlin-gcm-detection
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, staticIv))
        return cipher.doFinal(data.toByteArray())
    }
    
    val encrypted1 = encryptData("Secret message 1")
    val encrypted2 = encryptData("Secret message 2")
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=1}
fun bad_case_4() {
    // Using a hardcoded IV in a loop
    val key = KeyGenerator.getInstance("AES").generateKey()
    val hardcodedIv = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C)
    
    val messages = listOf("Message 1", "Message 2", "Message 3")
    val encryptedMessages = mutableListOf<ByteArray>()
    
    for (message in messages) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // ruleid: kotlin-gcm-detection
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, hardcodedIv))
        encryptedMessages.add(cipher.doFinal(message.toByteArray()))
    }
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=1}
fun bad_case_5() {
    // Using a constant IV from a constant variable
    val FIXED_IV = byteArrayOf(0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0)
    val key = KeyGenerator.getInstance("AES").generateKey()
    
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    // ruleid: kotlin-gcm-detection
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, FIXED_IV))
    val encrypted = cipher.doFinal("Sensitive information".toByteArray())
    
    // Later in the code, reusing the same IV
    val anotherCipher = Cipher.getInstance("AES/GCM/NoPadding")
    // ruleid: kotlin-gcm-detection
    anotherCipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, FIXED_IV))
    val anotherEncrypted = anotherCipher.doFinal("More sensitive information".toByteArray())
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=1}
fun bad_case_6() {
    // Using an IV derived from a predictable source
    val key = KeyGenerator.getInstance("AES").generateKey()
    val timestamp = System.currentTimeMillis().toString()
    val predictableIv = timestamp.substring(0, 12).toByteArray()
    
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    // ruleid: kotlin-gcm-detection
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, predictableIv))
    val encrypted = cipher.doFinal("Secret data".toByteArray())
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=1}
fun bad_case_7() {
    // Using an IV from a static method that always returns the same value
    val key = KeyGenerator.getInstance("AES").generateKey()
    
    fun getStaticIv(): ByteArray {
        return byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)
    }
    
    val cipher1 = Cipher.getInstance("AES/GCM/NoPadding")
    // ruleid: kotlin-gcm-detection
    cipher1.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, getStaticIv()))
    val encrypted1 = cipher1.doFinal("First secret".toByteArray())
    
    val cipher2 = Cipher.getInstance("AES/GCM/NoPadding")
    // ruleid: kotlin-gcm-detection
    cipher2.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, getStaticIv()))
    val encrypted2 = cipher2.doFinal("Second secret".toByteArray())
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=1}
fun bad_case_8() {
    // Using a counter-based IV that's too short and will eventually repeat
    val key = KeyGenerator.getInstance("AES").generateKey()
    var counter: Byte = 0
    
    fun encryptMessage(message: String): ByteArray {
        val iv = ByteArray(12) { counter }
        counter++  // This will eventually wrap around and repeat
        
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // ruleid: kotlin-gcm-detection
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        return cipher.doFinal(message.toByteArray())
    }
    
    val encrypted1 = encryptMessage("Secret data 1")
    val encrypted2 = encryptMessage("Secret data 2")
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=1}
fun bad_case_9() {
    // Using an IV stored in a configuration file that doesn't change
    val key = KeyGenerator.getInstance("AES").generateKey()
    
    // Simulating reading from a config file
    fun readIvFromConfig(): ByteArray {
        // In a real scenario, this would read from a file but always return the same value
        return byteArrayOf(9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2)
    }
    
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    // ruleid: kotlin-gcm-detection
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, readIvFromConfig()))
    val encrypted = cipher.doFinal("Confidential data".toByteArray())
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=1}
fun bad_case_10() {
    // Using an IV that's derived from the key (which doesn't change)
    val keyBytes = "ThisIsA32ByteKeyForAES256Encryption".toByteArray()
    val key = SecretKeySpec(keyBytes, "AES")
    
    // Deriving IV from the key (bad practice)
    val ivBytes = keyBytes.copyOfRange(0, 12)
    
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    // ruleid: kotlin-gcm-detection
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, ivBytes))
    val encrypted = cipher.doFinal("Sensitive information".toByteArray())
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=1}
fun bad_case_11() {
    // Using an IV that's stored in a database but never updated
    val key = KeyGenerator.getInstance("AES").generateKey()
    
    // Simulating fetching from a database
    fun getIvFromDatabase(): ByteArray {
        // In a real scenario, this would fetch from a database but always return the same value
        return byteArrayOf(3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8)
    }
    
    val cipher1 = Cipher.getInstance("AES/GCM/NoPadding")
    // ruleid: kotlin-gcm-detection
    cipher1.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, getIvFromDatabase()))
    val encrypted1 = cipher1.doFinal("First secret".toByteArray())
    
    val cipher2 = Cipher.getInstance("AES/GCM/NoPadding")
    // ruleid: kotlin-gcm-detection
    cipher2.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, getIvFromDatabase()))
    val encrypted2 = cipher2.doFinal("Second secret".toByteArray())
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=1}
fun bad_case_12() {
    // Using a zero IV
    val key = KeyGenerator.getInstance("AES").generateKey()
    val zeroIv = ByteArray(12) // All zeros by default
    
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    // ruleid: kotlin-gcm-detection
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, zeroIv))
    val encrypted = cipher.doFinal("Confidential information".toByteArray())
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=1}
fun bad_case_13() {
    // Using an IV that's derived from the plaintext (which is bad practice)
    val key = KeyGenerator.getInstance("AES").generateKey()
    
    fun encryptData(plaintext: String): ByteArray {
        // Deriving IV from the plaintext itself (very bad practice)
        val plaintextBytes = plaintext.toByteArray()
        val iv = if (plaintextBytes.size >= 12) {
            plaintextBytes.copyOfRange(0, 12)
        } else {
            val paddedIv = ByteArray(12)
            plaintextBytes.copyInto(paddedIv)
            paddedIv
        }
        
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // ruleid: kotlin-gcm-detection
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        return cipher.doFinal(plaintext.toByteArray())
    }
    
    val encrypted1 = encryptData("This is a secret message")
    val encrypted2 = encryptData("Another secret message")
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=1}
fun bad_case_14() {
    // Using an IV that's generated once at application startup
    val key = KeyGenerator.getInstance("AES").generateKey()
    
    // This would typically be generated once when the application starts
    val applicationWideIv = ByteArray(12).apply {
        SecureRandom().nextBytes(this)
    }
    
    fun encryptUserData(userData: String): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // ruleid: kotlin-gcm-detection
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, applicationWideIv))
        return cipher.doFinal(userData.toByteArray())
    }
    
    val encrypted1 = encryptUserData("User1's data")
    val encrypted2 = encryptUserData("User2's data")
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=1}
fun bad_case_15() {
    // Using an IV from a weak random number generator
    val key = KeyGenerator.getInstance("AES").generateKey()
    
    // Using a predictable random generator
    val weakRandom = java.util.Random(42) // Seeded with a constant
    val iv = ByteArray(12)
    weakRandom.nextBytes(iv)
    
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    // ruleid: kotlin-gcm-detection
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
    val encrypted = cipher.doFinal("Sensitive data".toByteArray())
    
    // Later, generating another IV with the same seed
    val sameWeakRandom = java.util.Random(42)
    val sameIv = ByteArray(12)
    sameWeakRandom.nextBytes(sameIv)
    
    val anotherCipher = Cipher.getInstance("AES/GCM/NoPadding")
    // ruleid: kotlin-gcm-detection
    anotherCipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, sameIv))
    val anotherEncrypted = anotherCipher.doFinal("More sensitive data".toByteArray())
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=0}
fun good_case_1() {
    // Generating a new random IV for each encryption
    val key = KeyGenerator.getInstance("AES").generateKey()
    
    val plaintext1 = "Sensitive data 1".toByteArray()
    val iv1 = ByteArray(12)
    SecureRandom().nextBytes(iv1)
    val cipher1 = Cipher.getInstance("AES/GCM/NoPadding")
    // ok: kotlin-gcm-detection
    cipher1.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv1))
    val ciphertext1 = cipher1.doFinal(plaintext1)
    
    val plaintext2 = "Sensitive data 2".toByteArray()
    val iv2 = ByteArray(12)
    SecureRandom().nextBytes(iv2)
    val cipher2 = Cipher.getInstance("AES/GCM/NoPadding")
    // ok: kotlin-gcm-detection
    cipher2.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv2))
    val ciphertext2 = cipher2.doFinal(plaintext2)
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=0}
fun good_case_2() {
    // Using a secure random IV for each encryption operation
    val key = "0123456789abcdef".toByteArray()
    val secretKey = SecretKeySpec(key, "AES")
    
    fun encrypt(message: String): Pair<ByteArray, ByteArray> {
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)
        val gcmSpec = GCMParameterSpec(128, iv)
        
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // ok: kotlin-gcm-detection
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
        val encrypted = cipher.doFinal(message.toByteArray())
        
        return Pair(iv, encrypted)
    }
    
    val (iv1, encrypted1) = encrypt("First message")
    val (iv2, encrypted2) = encrypt("Second message")
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=0}
fun good_case_3() {
    // Storing the IV with the ciphertext for later decryption
    val key = KeyGenerator.getInstance("AES").generateKey()
    
    fun encryptData(data: String): ByteArray {
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)
        
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // ok: kotlin-gcm-detection
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val encrypted = cipher.doFinal(data.toByteArray())
        
        // Prepend IV to the encrypted data for storage/transmission
        val result = ByteArray(iv.size + encrypted.size)
        System.arraycopy(iv, 0, result, 0, iv.size)
        System.arraycopy(encrypted, 0, result, iv.size, encrypted.size)
        
        return result
    }
    
    val encrypted1 = encryptData("Secret message 1")
    val encrypted2 = encryptData("Secret message 2")
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=0}
fun good_case_4() {
    // Using a counter-based approach with sufficient randomness
    val key = KeyGenerator.getInstance("AES").generateKey()
    val secureRandom = SecureRandom()
    
    // Generate a random base IV
    val baseIv = ByteArray(12)
    secureRandom.nextBytes(baseIv)
    
    // Use a counter to ensure uniqueness
    var counter = 0L
    
    fun encryptMessage(message: String): ByteArray {
        // Create a unique IV by combining the base IV with a counter
        val uniqueIv = baseIv.clone()
        
        // Modify the last 8 bytes with the counter value
        for (i in 0 until 8) {
            uniqueIv[uniqueIv.size - 1 - i] = ((counter shr (i * 8)) and 0xFF).toByte()
        }
        counter++
        
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // ok: kotlin-gcm-detection
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, uniqueIv))
        return cipher.doFinal(message.toByteArray())
    }
    
    val encrypted1 = encryptMessage("Secret data 1")
    val encrypted2 = encryptMessage("Secret data 2")
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=0}
fun good_case_5() {
    // Using a UUID-based IV generation approach
    val key = KeyGenerator.getInstance("AES").generateKey()
    
    fun generateIvFromUuid(): ByteArray {
        val uuid = java.util.UUID.randomUUID()
        val buffer = ByteArray(12)
        
        // Convert UUID most significant bits to first 8 bytes
        val msb = uuid.mostSignificantBits
        for (i in 0 until 8) {
            buffer[i] = ((msb shr (8 * (7 - i))) and 0xFF).toByte()
        }
        
        // Use first 4 bytes of least significant bits for the remaining 4 bytes
        val lsb = uuid.leastSignificantBits
        for (i in 0 until 4) {
            buffer[8 + i] = ((lsb shr (8 * (7 - i))) and 0xFF).toByte()
        }
        
        return buffer
    }
    
    val iv = generateIvFromUuid()
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    // ok: kotlin-gcm-detection
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
    val encrypted = cipher.doFinal("Sensitive information".toByteArray())
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=0}
fun good_case_6() {
    // Using a cryptographically secure random number generator for IV
    val key = KeyGenerator.getInstance("AES").generateKey()
    val secureRandom = SecureRandom.getInstanceStrong() // Using a strong instance
    
    val plaintext = "Secret information".toByteArray()
    val iv = ByteArray(12)
    secureRandom.nextBytes(iv)
    
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    // ok: kotlin-gcm-detection
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
    val ciphertext = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=0}
fun good_case_7() {
    // Using a timestamp with random data for IV generation
    val key = KeyGenerator.getInstance("AES").generateKey()
    
    fun generateTimestampedIv(): ByteArray {
        val iv = ByteArray(12)
        val timestamp = System.currentTimeMillis()
        
        // First 8 bytes from timestamp
        for (i in 0 until 8) {
            iv[i] = ((timestamp shr (i * 8)) and 0xFF).toByte()
        }
        
        // Last 4 bytes random
        SecureRandom().nextBytes(iv, 8, 4)
        return iv
    }
    
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val iv = generateTimestampedIv()
    // ok: kotlin-gcm-detection
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
    val encrypted = cipher.doFinal("Sensitive data".toByteArray())
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=0}
fun good_case_8() {
    // Using a database to store unique IVs to prevent reuse
    val key = KeyGenerator.getInstance("AES").generateKey()
    
    // Simulating a database of used IVs
    val usedIvs = mutableSetOf<String>()
    
    fun generateUniqueIv(): ByteArray {
        val iv = ByteArray(12)
        var ivBase64: String
        
        do {
            SecureRandom().nextBytes(iv)
            ivBase64 = Base64.getEncoder().encodeToString(iv)
        } while (usedIvs.contains(ivBase64))
        
        usedIvs.add(ivBase64)
        return iv
    }
    
    val iv = generateUniqueIv()
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    // ok: kotlin-gcm-detection
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
    val encrypted = cipher.doFinal("Confidential information".toByteArray())
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=0}
fun good_case_9() {
    // Using a nonce-based approach with a message counter
    val key = KeyGenerator.getInstance("AES").generateKey()
    
    // Generate a random nonce at startup
    val nonce = ByteArray(8)
    SecureRandom().nextBytes(nonce)
    
    var messageCounter = 0L
    
    fun encryptMessage(message: String): ByteArray {
        // Create IV by combining nonce with message counter
        val iv = ByteArray(12)
        System.arraycopy(nonce, 0, iv, 0, nonce.size)
        
        // Add counter to last 4 bytes
        for (i in 0 until 4) {
            iv[8 + i] = ((messageCounter shr (i * 8)) and 0xFF).toByte()
        }
        messageCounter++
        
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // ok: kotlin-gcm-detection
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        return cipher.doFinal(message.toByteArray())
    }
    
    val encrypted1 = encryptMessage("First message")
    val encrypted2 = encryptMessage("Second message")
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=0}
fun good_case_10() {
    // Using a key derivation function to generate both key and IV
    val masterKey = "ThisIsAMasterKeyForDerivedKeysAndIVs".toByteArray()
    val salt = "RandomSalt".toByteArray()
    
    fun deriveKeyAndIv(messageId: String): Pair<SecretKey, ByteArray> {
        // In a real scenario, this would use PBKDF2 or similar
        // This is a simplified example
        val messageIdBytes = messageId.toByteArray()
        
        // Create a unique input for each message
        val input = ByteArray(masterKey.size + salt.size + messageIdBytes.size)
        System.arraycopy(masterKey, 0, input, 0, masterKey.size)
        System.arraycopy(salt, 0, input, masterKey.size, salt.size)
        System.arraycopy(messageIdBytes, 0, input, masterKey.size + salt.size, messageIdBytes.size)
        
        // Use a hash function to derive key material
        val md = java.security.MessageDigest.getInstance("SHA-256")
        val digest = md.digest(input)
        
        // Use first 16 bytes for key, next 12 for IV
        val keyBytes = digest.copyOfRange(0, 16)
        val ivBytes = digest.copyOfRange(16, 28)
        
        val key = SecretKeySpec(keyBytes, "AES")
        return Pair(key, ivBytes)
    }
    
    val (key1, iv1) = deriveKeyAndIv("message1")
    val cipher1 = Cipher.getInstance("AES/GCM/NoPadding")
    // ok: kotlin-gcm-detection
    cipher1.init(Cipher.ENCRYPT_MODE, key1, GCMParameterSpec(128, iv1))
    val encrypted1 = cipher1.doFinal("First message".toByteArray())
    
    val (key2, iv2) = deriveKeyAndIv("message2")
    val cipher2 = Cipher.getInstance("AES/GCM/NoPadding")
    // ok: kotlin-gcm-detection
    cipher2.init(Cipher.ENCRYPT_MODE, key2, GCMParameterSpec(128, iv2))
    val encrypted2 = cipher2.doFinal("Second message".toByteArray())
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=0}
fun good_case_11() {
    // Using a secure encryption wrapper class
    class SecureGcmEncryption(private val key: SecretKey) {
        fun encrypt(plaintext: ByteArray): Pair<ByteArray, ByteArray> {
            val iv = ByteArray(12)
            SecureRandom().nextBytes(iv)
            
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            // ok: kotlin-gcm-detection
            cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
            val ciphertext = cipher.doFinal(plaintext)
            
            return Pair(iv, ciphertext)
        }
    }
    
    val key = KeyGenerator.getInstance("AES").generateKey()
    val encryptor = SecureGcmEncryption(key)
    
    val (iv1, encrypted1) = encryptor.encrypt("First secret".toByteArray())
    val (iv2, encrypted2) = encryptor.encrypt("Second secret".toByteArray())
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=0}
fun good_case_12() {
    // Using a secure encryption with IV rotation strategy
    val key = KeyGenerator.getInstance("AES").generateKey()
    val secureRandom = SecureRandom()
    
    // A class to manage IV rotation
    class IvManager {
        private val usedIvs = mutableSetOf<String>()
        private val maxStoredIvs = 1000 // Limit storage to prevent memory issues
        
        fun generateIv(): ByteArray {
            val iv = ByteArray(12)
            var ivHex: String
            
            do {
                secureRandom.nextBytes(iv)
                ivHex = iv.joinToString("") { "%02x".format(it) }
            } while (usedIvs.contains(ivHex))
            
            // Store the IV
            usedIvs.add(ivHex)
            
            // Clean up old IVs if we exceed our limit
            if (usedIvs.size > maxStoredIvs) {
                usedIvs.clear() // In a real implementation, you might use a more sophisticated strategy
            }
            
            return iv
        }
    }
    
    val ivManager = IvManager()
    
    val iv = ivManager.generateIv()
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    // ok: kotlin-gcm-detection
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
    val encrypted = cipher.doFinal("Sensitive data".toByteArray())
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=0}
fun good_case_13() {
    // Using hardware-based random number generation for IV when available
    val key = KeyGenerator.getInstance("AES").generateKey()
    
    fun getSecureRandomIv(): ByteArray {
        val iv = ByteArray(12)
        try {
            // Try to use hardware-based RNG if available
            val secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN")
            secureRandom.nextBytes(iv)
        } catch (e: Exception) {
            // Fall back to default SecureRandom
            SecureRandom().nextBytes(iv)
        }
        return iv
    }
    
    val iv = getSecureRandomIv()
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    // ok: kotlin-gcm-detection
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
    val encrypted = cipher.doFinal("Confidential information".toByteArray())
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=0}
fun good_case_14() {
    // Using a combination of device ID and random data for IV
    val key = KeyGenerator.getInstance("AES").generateKey()
    
    fun generateDeviceSpecificIv(): ByteArray {
        val deviceId = "unique-device-id-12345" // In a real app, this would be a real device ID
        val deviceIdHash = java.security.MessageDigest.getInstance("SHA-256")
            .digest(deviceId.toByteArray())
        
        // Use first 4 bytes of device ID hash
        val iv = ByteArray(12)
        System.arraycopy(deviceIdHash, 0, iv, 0, 4)
        
        // Fill the rest with random data
        SecureRandom().nextBytes(iv, 4, 8)
        return iv
    }
    
    val iv = generateDeviceSpecificIv()
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    // ok: kotlin-gcm-detection
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
    val encrypted = cipher.doFinal("Sensitive data".toByteArray())
}
// {/fact}

// {fact rule=reusing_nonce_key_pair_encryption@v1.0 defects=0}
fun good_case_15() {
    // Using a secure encryption service with proper IV management
    class EncryptionService {
        private val key: SecretKey
        
        init {
            val keyGenerator = KeyGenerator.getInstance("AES")
            keyGenerator.init(256)
            key = keyGenerator.generateKey()
        }
        
        fun encrypt(data: String): EncryptedData {
            val iv = ByteArray(12)
            SecureRandom().nextBytes(iv)
            
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            // ok: kotlin-gcm-detection
            cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
            val encryptedBytes = cipher.doFinal(data.toByteArray())
            
            return EncryptedData(iv, encryptedBytes)
        }
        
        data class EncryptedData(val iv: ByteArray, val ciphertext: ByteArray)
    }
    
    val encryptionService = EncryptionService()
    val encryptedData1 = encryptionService.encrypt("First secret message")
    val encryptedData2 = encryptionService.encrypt("Second secret message")
}
// {/fact}