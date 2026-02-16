import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import java.util.Base64
import javax.crypto.spec.IvParameterSpec
import javax.crypto.Mac
import java.security.NoSuchAlgorithmException
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.mindrot.jbcrypt.BCrypt

// True Positives (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_1() {
    val input = "sensitive data"
    val md = MessageDigest.getInstance("MD5")
    // ruleid: kotlin-use-of-weak-hashes
    val hash = md.digest(input.toByteArray())
    println("MD5 hash: ${hash.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_2() {
    val password = "user_password"
    val md = MessageDigest.getInstance("SHA1")
    // ruleid: kotlin-use-of-weak-hashes
    val hashedPassword = md.digest(password.toByteArray())
    println("SHA-1 hash: ${hashedPassword.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_3() {
    val secretKey = "mysecretkey12345"
    val keySpec = SecretKeySpec(secretKey.toByteArray(), "AES")
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    // ruleid: kotlin-use-of-weak-hashes
    cipher.init(Cipher.ENCRYPT_MODE, keySpec)
    val encrypted = cipher.doFinal("sensitive data".toByteArray())
    println("Encrypted: ${Base64.getEncoder().encodeToString(encrypted)}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_4() {
    val data = "confidential information"
    val digest = MessageDigest.getInstance("md5")
    // ruleid: kotlin-use-of-weak-hashes
    val result = digest.digest(data.toByteArray())
    println("Hash: ${result.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_5() {
    val userCredentials = "username:password"
    val messageDigest = MessageDigest.getInstance("SHA1")
    // ruleid: kotlin-use-of-weak-hashes
    val hashedCredentials = messageDigest.digest(userCredentials.toByteArray())
    println("Hashed credentials: ${hashedCredentials.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_6() {
    val key = "0123456789abcdef".toByteArray()
    val keySpec = SecretKeySpec(key, "AES")
    val cipher = Cipher.getInstance("AES/ECB/NoPadding")
    // ruleid: kotlin-use-of-weak-hashes
    cipher.init(Cipher.ENCRYPT_MODE, keySpec)
    val cipherText = cipher.doFinal("This is a secret message".toByteArray())
    println("Encrypted: ${Base64.getEncoder().encodeToString(cipherText)}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_7() {
    val userData = "user123:pass456"
    val algorithm = "MD5"
    val md = MessageDigest.getInstance(algorithm)
    // ruleid: kotlin-use-of-weak-hashes
    val hash = md.digest(userData.toByteArray())
    println("Hash: ${hash.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_8() {
    val sensitiveData = "credit card number"
    val keyBytes = "secretkey1234567".toByteArray()
    val keySpec = SecretKeySpec(keyBytes, "AES")
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    // ruleid: kotlin-use-of-weak-hashes
    cipher.init(Cipher.ENCRYPT_MODE, keySpec)
    val encrypted = cipher.doFinal(sensitiveData.toByteArray())
    println("Encrypted data: ${Base64.getEncoder().encodeToString(encrypted)}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_9() {
    val message = "important message"
    val md = MessageDigest.getInstance("SHA-1")
    // ruleid: kotlin-use-of-weak-hashes
    val digest = md.digest(message.toByteArray())
    println("SHA-1 digest: ${digest.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_10() {
    val data = "sensitive information"
    val algorithm = if (data.length > 20) "SHA-256" else "MD5"
    val md = MessageDigest.getInstance(algorithm)
    // ruleid: kotlin-use-of-weak-hashes
    val hash = md.digest(data.toByteArray())
    println("Hash: ${hash.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_11() {
    val password = "mySecurePassword"
    val salt = "randomSalt"
    val md = MessageDigest.getInstance("SHA1")
    md.update(salt.toByteArray())
    // ruleid: kotlin-use-of-weak-hashes
    val hashedPassword = md.digest(password.toByteArray())
    println("Salted hash: ${hashedPassword.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_12() {
    val secretMessage = "top secret info"
    val key = SecretKeySpec("0123456789abcdef".toByteArray(), "AES")
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    // ruleid: kotlin-use-of-weak-hashes
    cipher.init(Cipher.ENCRYPT_MODE, key)
    val encryptedData = cipher.doFinal(secretMessage.toByteArray())
    println("Encrypted: ${Base64.getEncoder().encodeToString(encryptedData)}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_13() {
    val input = "user input"
    val md5 = MessageDigest.getInstance("MD5")
    // ruleid: kotlin-use-of-weak-hashes
    val hash = md5.digest(input.toByteArray())
    val hexString = StringBuilder()
    for (b in hash) {
        hexString.append(String.format("%02x", b))
    }
    println("MD5 hash: $hexString")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_14() {
    val userInput = "sensitive data"
    val key = "mykey1234567890".toByteArray()
    val skeySpec = SecretKeySpec(key, "AES")
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    // ruleid: kotlin-use-of-weak-hashes
    cipher.init(Cipher.ENCRYPT_MODE, skeySpec)
    val encrypted = cipher.doFinal(userInput.toByteArray())
    println("Encrypted: ${Base64.getEncoder().encodeToString(encrypted)}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_15() {
    val data = "confidential data"
    val algorithms = listOf("MD5", "SHA-256", "SHA-1")
    val selectedAlgo = algorithms[0] // Selecting MD5
    val md = MessageDigest.getInstance(selectedAlgo)
    // ruleid: kotlin-use-of-weak-hashes
    val hash = md.digest(data.toByteArray())
    println("Hash using $selectedAlgo: ${hash.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_1() {
    val input = "sensitive data"
    val md = MessageDigest.getInstance("SHA-256")
    // ok: kotlin-use-of-weak-hashes
    val hash = md.digest(input.toByteArray())
    println("SHA-256 hash: ${hash.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_2() {
    val password = "user_password"
    // ok: kotlin-use-of-weak-hashes
    val hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt())
    println("BCrypt hash: $hashedPassword")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_3() {
    val secretKey = "mysecretkey12345"
    val keySpec = SecretKeySpec(secretKey.toByteArray(), "AES")
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val iv = ByteArray(12)
    SecureRandom().nextBytes(iv)
    val ivSpec = IvParameterSpec(iv)
    // ok: kotlin-use-of-weak-hashes
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
    val encrypted = cipher.doFinal("sensitive data".toByteArray())
    println("Encrypted: ${Base64.getEncoder().encodeToString(encrypted)}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_4() {
    val data = "confidential information"
    val digest = MessageDigest.getInstance("SHA-512")
    // ok: kotlin-use-of-weak-hashes
    val result = digest.digest(data.toByteArray())
    println("Hash: ${result.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_5() {
    val password = "userPassword"
    val salt = ByteArray(16)
    SecureRandom().nextBytes(salt)
    
    // ok: kotlin-use-of-weak-hashes
    val builder = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
        .withSalt(salt)
        .withIterations(10)
        .withMemoryAsKB(65536)
        .withParallelism(4)
    
    val generator = Argon2BytesGenerator()
    generator.init(builder.build())
    
    val hash = ByteArray(32)
    generator.generateBytes(password.toByteArray(), hash)
    println("Argon2 hash: ${hash.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_6() {
    val key = "0123456789abcdef".toByteArray()
    val keySpec = SecretKeySpec(key, "AES")
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val iv = ByteArray(12)
    SecureRandom().nextBytes(iv)
    val ivSpec = IvParameterSpec(iv)
    // ok: kotlin-use-of-weak-hashes
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
    val cipherText = cipher.doFinal("This is a secret message".toByteArray())
    println("Encrypted: ${Base64.getEncoder().encodeToString(cipherText)}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_7() {
    val userData = "user123:pass456"
    val algorithm = "SHA-256"
    val md = MessageDigest.getInstance(algorithm)
    // ok: kotlin-use-of-weak-hashes
    val hash = md.digest(userData.toByteArray())
    println("Hash: ${hash.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_8() {
    val sensitiveData = "credit card number"
    val keyBytes = "secretkey1234567".toByteArray()
    val keySpec = SecretKeySpec(keyBytes, "AES")
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val iv = ByteArray(16)
    SecureRandom().nextBytes(iv)
    val ivSpec = IvParameterSpec(iv)
    // ok: kotlin-use-of-weak-hashes
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
    val encrypted = cipher.doFinal(sensitiveData.toByteArray())
    println("Encrypted data: ${Base64.getEncoder().encodeToString(encrypted)}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_9() {
    val message = "important message"
    val md = MessageDigest.getInstance("SHA-3-256")
    // ok: kotlin-use-of-weak-hashes
    val digest = md.digest(message.toByteArray())
    println("SHA-3-256 digest: ${digest.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_10() {
    val password = "mySecurePassword"
    // ok: kotlin-use-of-weak-hashes
    val hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(12))
    val isValid = BCrypt.checkpw(password, hashedPassword)
    println("Password valid: $isValid")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_11() {
    val secretKey = KeyGenerator.getInstance("AES").generateKey()
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val iv = ByteArray(16)
    SecureRandom().nextBytes(iv)
    val ivSpec = IvParameterSpec(iv)
    // ok: kotlin-use-of-weak-hashes
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
    val encrypted = cipher.doFinal("sensitive data".toByteArray())
    println("Encrypted: ${Base64.getEncoder().encodeToString(encrypted)}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_12() {
    val message = "authenticate this message"
    val secretKey = "secret".toByteArray()
    val keySpec = SecretKeySpec(secretKey, "HmacSHA256")
    val mac = Mac.getInstance("HmacSHA256")
    // ok: kotlin-use-of-weak-hashes
    mac.init(keySpec)
    val hmac = mac.doFinal(message.toByteArray())
    println("HMAC: ${hmac.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_13() {
    val input = "user input"
    val md = MessageDigest.getInstance("SHA-512")
    // ok: kotlin-use-of-weak-hashes
    val hash = md.digest(input.toByteArray())
    val hexString = StringBuilder()
    for (b in hash) {
        hexString.append(String.format("%02x", b))
    }
    println("SHA-512 hash: $hexString")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_14() {
    val userInput = "sensitive data"
    val key = KeyGenerator.getInstance("AES").generateKey()
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val iv = ByteArray(12)
    SecureRandom().nextBytes(iv)
    val ivSpec = IvParameterSpec(iv)
    // ok: kotlin-use-of-weak-hashes
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
    val encrypted = cipher.doFinal(userInput.toByteArray())
    println("Encrypted: ${Base64.getEncoder().encodeToString(encrypted)}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_15() {
    val data = "confidential data"
    val algorithms = listOf("SHA-256", "SHA-512", "SHA3-256")
    val selectedAlgo = algorithms[0] // Selecting SHA-256
    val md = MessageDigest.getInstance(selectedAlgo)
    // ok: kotlin-use-of-weak-hashes
    val hash = md.digest(data.toByteArray())
    println("Hash using $selectedAlgo: ${hash.joinToString("") { "%02x".format(it) }}")
}
// {/fact}