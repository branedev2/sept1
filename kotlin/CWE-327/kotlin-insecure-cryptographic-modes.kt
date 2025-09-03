import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.Base64
import javax.crypto.spec.GCMParameterSpec

// True Positives (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_1() {
    val key = "0123456789abcdef".toByteArray()
    val keySpec = SecretKeySpec(key, "AES")
    
    // ruleid: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keySpec)
    
    val plaintext = "Sensitive data".toByteArray()
    val ciphertext = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_2() {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(256)
    val secretKey = keyGenerator.generateKey()
    
    // ruleid: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/CTR/NoPadding")
    val iv = ByteArray(16)
    val ivSpec = IvParameterSpec(iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
    
    val data = "Secret message".toByteArray()
    val encrypted = cipher.doFinal(data)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_3() {
    val key = "ThisIsA32ByteKeyForAES256Padding".toByteArray()
    val secretKeySpec = SecretKeySpec(key, "AES")
    
    // ruleid: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/ECB/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec)
    
    val plainText = "This is a test message for encryption".toByteArray()
    val cipherText = cipher.doFinal(plainText)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_4() {
    val keyGen = KeyGenerator.getInstance("DES")
    keyGen.init(56)
    val secretKey = keyGen.generateKey()
    
    // ruleid: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    
    val plaintext = "Confidential information".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_5() {
    val key = "0123456789abcdef".toByteArray()
    val keySpec = SecretKeySpec(key, "AES")
    val iv = ByteArray(16)
    val ivSpec = IvParameterSpec(iv)
    
    // ruleid: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/CTR/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
    
    val data = "Top secret".toByteArray()
    val encrypted = cipher.doFinal(data)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_6() {
    val key = ByteArray(16).apply { SecureRandom().nextBytes(this) }
    val secretKey = SecretKeySpec(key, "AES")
    
    // ruleid: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/ECB/ISO10126Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    
    val plaintext = "Sensitive customer data".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_7() {
    val keyGenerator = KeyGenerator.getInstance("DESede") // Triple DES
    keyGenerator.init(168)
    val secretKey = keyGenerator.generateKey()
    
    // ruleid: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    
    val plaintext = "Financial records".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_8() {
    val key = "0123456789abcdef".toByteArray()
    val keySpec = SecretKeySpec(key, "Blowfish")
    
    // ruleid: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keySpec)
    
    val plaintext = "Personal information".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_9() {
    val key = ByteArray(16).apply { SecureRandom().nextBytes(this) }
    val secretKey = SecretKeySpec(key, "RC4")
    
    // ruleid: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("RC4")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    
    val plaintext = "User credentials".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_10() {
    val key = "0123456789abcdef".toByteArray()
    val keySpec = SecretKeySpec(key, "AES")
    val iv = ByteArray(16)
    val ivSpec = IvParameterSpec(iv)
    
    // ruleid: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/OFB/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
    
    val plaintext = "Credit card numbers".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_11() {
    val key = ByteArray(16).apply { SecureRandom().nextBytes(this) }
    val secretKey = SecretKeySpec(key, "RC2")
    
    // ruleid: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("RC2/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    
    val plaintext = "Authentication tokens".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_12() {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(128)
    val secretKey = keyGenerator.generateKey()
    
    // ruleid: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/CBC/NoPadding")
    val iv = ByteArray(16)
    val ivSpec = IvParameterSpec(iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
    
    val plaintext = "Sensitive health data".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_13() {
    val cipherMode = "ECB"
    val key = "0123456789abcdef".toByteArray()
    val keySpec = SecretKeySpec(key, "AES")
    
    // ruleid: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/$cipherMode/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keySpec)
    
    val plaintext = "Password hash".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_14() {
    val algorithm = "AES"
    val mode = "CTR"
    val padding = "NoPadding"
    val key = ByteArray(16).apply { SecureRandom().nextBytes(this) }
    val secretKey = SecretKeySpec(key, algorithm)
    val iv = ByteArray(16)
    val ivSpec = IvParameterSpec(iv)
    
    // ruleid: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("$algorithm/$mode/$padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
    
    val plaintext = "API keys".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_15() {
    val key = "0123456789abcdef".toByteArray()
    val keySpec = SecretKeySpec(key, "AES")
    
    val cipherString = StringBuilder()
    cipherString.append("AES/")
    cipherString.append("ECB/")
    cipherString.append("PKCS5Padding")
    
    // ruleid: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance(cipherString.toString())
    cipher.init(Cipher.ENCRYPT_MODE, keySpec)
    
    val plaintext = "Private messages".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_1() {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(256)
    val secretKey = keyGenerator.generateKey()
    
    // ok: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val iv = ByteArray(12).apply { SecureRandom().nextBytes(this) }
    val gcmSpec = GCMParameterSpec(128, iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
    
    val plaintext = "Sensitive data".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_2() {
    val key = ByteArray(32).apply { SecureRandom().nextBytes(this) }
    val secretKey = SecretKeySpec(key, "AES")
    val iv = ByteArray(16).apply { SecureRandom().nextBytes(this) }
    val ivSpec = IvParameterSpec(iv)
    
    // ok: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
    
    val plaintext = "Secret message".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_3() {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(256, SecureRandom())
    val secretKey = keyGenerator.generateKey()
    
    // ok: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/GCM/PKCS5Padding")
    val iv = ByteArray(12).apply { SecureRandom().nextBytes(this) }
    val gcmSpec = GCMParameterSpec(128, iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
    
    val plaintext = "This is a test message for encryption".toByteArray()
    val cipherText = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_4() {
    val key = ByteArray(32).apply { SecureRandom().nextBytes(this) }
    val secretKey = SecretKeySpec(key, "AES")
    val iv = ByteArray(16).apply { SecureRandom().nextBytes(this) }
    val ivSpec = IvParameterSpec(iv)
    
    // ok: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
    
    val plaintext = "Confidential information".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_5() {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(256)
    val secretKey = keyGenerator.generateKey()
    
    // ok: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/CFB/PKCS5Padding")
    val iv = ByteArray(16).apply { SecureRandom().nextBytes(this) }
    val ivSpec = IvParameterSpec(iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
    
    val data = "Top secret".toByteArray()
    val encrypted = cipher.doFinal(data)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_6() {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(256)
    val secretKey = keyGenerator.generateKey()
    
    // ok: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val iv = ByteArray(12).apply { SecureRandom().nextBytes(this) }
    val gcmSpec = GCMParameterSpec(128, iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
    
    val plaintext = "Sensitive customer data".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
    val authTag = cipher.getParameters().getParameterSpec(GCMParameterSpec::class.java).iv
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_7() {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(256)
    val secretKey = keyGenerator.generateKey()
    
    // ok: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val iv = ByteArray(16).apply { SecureRandom().nextBytes(this) }
    val ivSpec = IvParameterSpec(iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
    
    val plaintext = "Financial records".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_8() {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(256)
    val secretKey = keyGenerator.generateKey()
    
    // ok: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/CFB8/PKCS5Padding")
    val iv = ByteArray(16).apply { SecureRandom().nextBytes(this) }
    val ivSpec = IvParameterSpec(iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
    
    val plaintext = "Personal information".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_9() {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(256)
    val secretKey = keyGenerator.generateKey()
    
    // ok: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val iv = ByteArray(12).apply { SecureRandom().nextBytes(this) }
    val gcmSpec = GCMParameterSpec(128, iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
    
    val plaintext = "User credentials".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_10() {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(256)
    val secretKey = keyGenerator.generateKey()
    
    val algorithm = "AES"
    val mode = "GCM"
    val padding = "NoPadding"
    
    // ok: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("$algorithm/$mode/$padding")
    val iv = ByteArray(12).apply { SecureRandom().nextBytes(this) }
    val gcmSpec = GCMParameterSpec(128, iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
    
    val plaintext = "Credit card numbers".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_11() {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(256)
    val secretKey = keyGenerator.generateKey()
    
    // ok: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val iv = ByteArray(16).apply { SecureRandom().nextBytes(this) }
    val ivSpec = IvParameterSpec(iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
    
    val plaintext = "Authentication tokens".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_12() {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(256)
    val secretKey = keyGenerator.generateKey()
    
    val cipherString = StringBuilder()
    cipherString.append("AES/")
    cipherString.append("GCM/")
    cipherString.append("NoPadding")
    
    // ok: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance(cipherString.toString())
    val iv = ByteArray(12).apply { SecureRandom().nextBytes(this) }
    val gcmSpec = GCMParameterSpec(128, iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
    
    val plaintext = "Sensitive health data".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_13() {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(256)
    val secretKey = keyGenerator.generateKey()
    
    // ok: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val iv = ByteArray(16).apply { SecureRandom().nextBytes(this) }
    val ivSpec = IvParameterSpec(iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
    
    val plaintext = "Password hash".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_14() {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(256)
    val secretKey = keyGenerator.generateKey()
    
    val secureMode = "GCM"
    
    // ok: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/$secureMode/NoPadding")
    val iv = ByteArray(12).apply { SecureRandom().nextBytes(this) }
    val gcmSpec = GCMParameterSpec(128, iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
    
    val plaintext = "API keys".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_15() {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(256)
    val secretKey = keyGenerator.generateKey()
    
    // ok: kotlin-insecure-cryptographic-modes
    val cipher = Cipher.getInstance("AES/CFB/PKCS5Padding")
    val iv = ByteArray(16).apply { SecureRandom().nextBytes(this) }
    val ivSpec = IvParameterSpec(iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
    
    val plaintext = "Private messages".toByteArray()
    val encrypted = cipher.doFinal(plaintext)
}
// {/fact}