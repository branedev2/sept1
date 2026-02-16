import java.security.KeyPairGenerator
import java.security.KeyPair
import java.security.SecureRandom
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.Cipher
import java.math.BigInteger
import java.security.interfaces.RSAPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.KeyFactory
import java.security.spec.RSAPublicKeySpec
import java.security.spec.RSAPrivateKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

// True Positive Examples (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_1() {
    // Using a weak 512-bit RSA key
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    // ruleid: kotlin-use-of-weak-rsa-key
    keyPairGenerator.initialize(512)
    val keyPair = keyPairGenerator.generateKeyPair()
    
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
    val encrypted = cipher.doFinal("Sensitive data".toByteArray())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_2() {
    // Using a weak 1024-bit RSA key with SecureRandom
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    val secureRandom = SecureRandom()
    // ruleid: kotlin-use-of-weak-rsa-key
    keyPairGenerator.initialize(1024, secureRandom)
    val keyPair = keyPairGenerator.generateKeyPair()
    
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
    val encrypted = cipher.doFinal("Sensitive data".toByteArray())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_3() {
    // Using a weak 256-bit RSA key with RSAKeyGenParameterSpec
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    // ruleid: kotlin-use-of-weak-rsa-key
    keyPairGenerator.initialize(RSAKeyGenParameterSpec(256, RSAKeyGenParameterSpec.F4))
    val keyPair = keyPairGenerator.generateKeyPair()
    
    // Use the key for digital signature
    val signature = java.security.Signature.getInstance("SHA256withRSA")
    signature.initSign(keyPair.private)
    signature.update("Data to sign".toByteArray())
    val signatureBytes = signature.sign()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_4() {
    // Using a weak 512-bit RSA key in a function that generates keys for a certificate
    fun generateCertificateKeyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        // ruleid: kotlin-use-of-weak-rsa-key
        keyPairGenerator.initialize(512)
        return keyPairGenerator.generateKeyPair()
    }
    
    val keyPair = generateCertificateKeyPair()
    // Use the key pair for a certificate
    val publicKey = keyPair.public as RSAPublicKey
    println("Certificate key size: ${publicKey.modulus.bitLength()}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_5() {
    // Using a weak 1024-bit RSA key with variable
    val keySize = 1024
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    // ruleid: kotlin-use-of-weak-rsa-key
    keyPairGenerator.initialize(keySize)
    val keyPair = keyPairGenerator.generateKeyPair()
    
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
    val encrypted = cipher.doFinal("Sensitive data".toByteArray())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_6() {
    // Using a weak 512-bit RSA key in a class
    class KeyManager {
        fun generateRSAKey(): KeyPair {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            // ruleid: kotlin-use-of-weak-rsa-key
            keyPairGenerator.initialize(512)
            return keyPairGenerator.generateKeyPair()
        }
    }
    
    val keyManager = KeyManager()
    val keyPair = keyManager.generateRSAKey()
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_7() {
    // Using a weak 1024-bit RSA key with a constant
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    val WEAK_KEY_SIZE = 1024
    // ruleid: kotlin-use-of-weak-rsa-key
    keyPairGenerator.initialize(WEAK_KEY_SIZE)
    val keyPair = keyPairGenerator.generateKeyPair()
    
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_8() {
    // Using a weak 512-bit RSA key with conditional logic
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    val useStrongKey = false
    
    if (useStrongKey) {
        keyPairGenerator.initialize(2048)
    } else {
        // ruleid: kotlin-use-of-weak-rsa-key
        keyPairGenerator.initialize(512)
    }
    
    val keyPair = keyPairGenerator.generateKeyPair()
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_9() {
    // Using a weak 1024-bit RSA key with a computed value
    val baseKeySize = 512
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    // ruleid: kotlin-use-of-weak-rsa-key
    keyPairGenerator.initialize(baseKeySize * 2) // 1024 bits
    val keyPair = keyPairGenerator.generateKeyPair()
    
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_10() {
    // Using a weak 512-bit RSA key with try-catch
    try {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        // ruleid: kotlin-use-of-weak-rsa-key
        keyPairGenerator.initialize(512)
        val keyPair = keyPairGenerator.generateKeyPair()
        
        // Use the key for encryption
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_11() {
    // Using a weak 1024-bit RSA key with a function parameter
    fun generateKey(keySize: Int): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(keySize)
        return keyPairGenerator.generateKeyPair()
    }
    
    // ruleid: kotlin-use-of-weak-rsa-key
    val keyPair = generateKey(1024)
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_12() {
    // Using a weak 512-bit RSA key with a lambda
    val keyGenerator = { size: Int ->
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(size)
        keyPairGenerator.generateKeyPair()
    }
    
    // ruleid: kotlin-use-of-weak-rsa-key
    val keyPair = keyGenerator(512)
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_13() {
    // Using a weak 1024-bit RSA key with RSAKeyGenParameterSpec and BigInteger exponent
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    val publicExponent = BigInteger.valueOf(65537)
    // ruleid: kotlin-use-of-weak-rsa-key
    keyPairGenerator.initialize(RSAKeyGenParameterSpec(1024, publicExponent))
    val keyPair = keyPairGenerator.generateKeyPair()
    
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_14() {
    // Using a weak 512-bit RSA key with a when expression
    val securityLevel = "low"
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    
    val keySize = when (securityLevel) {
        "high" -> 2048
        "medium" -> 1024
        else -> 512
    }
    
    // ruleid: kotlin-use-of-weak-rsa-key
    keyPairGenerator.initialize(keySize)
    val keyPair = keyPairGenerator.generateKeyPair()
    
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_15() {
    // Using a weak 1024-bit RSA key with custom key specs
    val keyFactory = KeyFactory.getInstance("RSA")
    val modulus = BigInteger("12345678901234567890123456789012345678901234567890", 16)
    val publicExponent = BigInteger("65537")
    val privateExponent = BigInteger("1234567890123456789012345678901234567890123456", 16)
    
    // Creating 1024-bit equivalent RSA key specs
    // ruleid: kotlin-use-of-weak-rsa-key
    val publicKeySpec = RSAPublicKeySpec(modulus, publicExponent)
    val privateKeySpec = RSAPrivateKeySpec(modulus, privateExponent)
    
    val publicKey = keyFactory.generatePublic(publicKeySpec)
    val privateKey = keyFactory.generatePrivate(privateKeySpec)
    
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    val encrypted = cipher.doFinal("Sensitive data".toByteArray())
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_1() {
    // Using a secure 2048-bit RSA key
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    // ok: kotlin-use-of-weak-rsa-key
    keyPairGenerator.initialize(2048)
    val keyPair = keyPairGenerator.generateKeyPair()
    
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
    val encrypted = cipher.doFinal("Sensitive data".toByteArray())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_2() {
    // Using a secure 3072-bit RSA key with SecureRandom
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    val secureRandom = SecureRandom()
    // ok: kotlin-use-of-weak-rsa-key
    keyPairGenerator.initialize(3072, secureRandom)
    val keyPair = keyPairGenerator.generateKeyPair()
    
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
    val encrypted = cipher.doFinal("Sensitive data".toByteArray())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_3() {
    // Using a secure 4096-bit RSA key with RSAKeyGenParameterSpec
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    // ok: kotlin-use-of-weak-rsa-key
    keyPairGenerator.initialize(RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4))
    val keyPair = keyPairGenerator.generateKeyPair()
    
    // Use the key for digital signature
    val signature = java.security.Signature.getInstance("SHA256withRSA")
    signature.initSign(keyPair.private)
    signature.update("Data to sign".toByteArray())
    val signatureBytes = signature.sign()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_4() {
    // Using a secure 2048-bit RSA key in a function that generates keys for a certificate
    fun generateCertificateKeyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        // ok: kotlin-use-of-weak-rsa-key
        keyPairGenerator.initialize(2048)
        return keyPairGenerator.generateKeyPair()
    }
    
    val keyPair = generateCertificateKeyPair()
    // Use the key pair for a certificate
    val publicKey = keyPair.public as RSAPublicKey
    println("Certificate key size: ${publicKey.modulus.bitLength()}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_5() {
    // Using a secure 3072-bit RSA key with variable
    val keySize = 3072
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    // ok: kotlin-use-of-weak-rsa-key
    keyPairGenerator.initialize(keySize)
    val keyPair = keyPairGenerator.generateKeyPair()
    
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
    val encrypted = cipher.doFinal("Sensitive data".toByteArray())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_6() {
    // Using a secure 2048-bit RSA key in a class
    class KeyManager {
        fun generateRSAKey(): KeyPair {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            // ok: kotlin-use-of-weak-rsa-key
            keyPairGenerator.initialize(2048)
            return keyPairGenerator.generateKeyPair()
        }
    }
    
    val keyManager = KeyManager()
    val keyPair = keyManager.generateRSAKey()
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_7() {
    // Using a secure 4096-bit RSA key with a constant
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    val STRONG_KEY_SIZE = 4096
    // ok: kotlin-use-of-weak-rsa-key
    keyPairGenerator.initialize(STRONG_KEY_SIZE)
    val keyPair = keyPairGenerator.generateKeyPair()
    
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_8() {
    // Using a secure 2048-bit RSA key with conditional logic
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    val useStrongKey = true
    
    if (useStrongKey) {
        // ok: kotlin-use-of-weak-rsa-key
        keyPairGenerator.initialize(2048)
    } else {
        keyPairGenerator.initialize(1024)
    }
    
    val keyPair = keyPairGenerator.generateKeyPair()
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_9() {
    // Using a secure 3072-bit RSA key with a computed value
    val baseKeySize = 1024
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    // ok: kotlin-use-of-weak-rsa-key
    keyPairGenerator.initialize(baseKeySize * 3) // 3072 bits
    val keyPair = keyPairGenerator.generateKeyPair()
    
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_10() {
    // Using a secure 2048-bit RSA key with try-catch
    try {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        // ok: kotlin-use-of-weak-rsa-key
        keyPairGenerator.initialize(2048)
        val keyPair = keyPairGenerator.generateKeyPair()
        
        // Use the key for encryption
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_11() {
    // Using a secure 4096-bit RSA key with a function parameter
    fun generateKey(keySize: Int): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(keySize)
        return keyPairGenerator.generateKeyPair()
    }
    
    // ok: kotlin-use-of-weak-rsa-key
    val keyPair = generateKey(4096)
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_12() {
    // Using a secure 3072-bit RSA key with a lambda
    val keyGenerator = { size: Int ->
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(size)
        keyPairGenerator.generateKeyPair()
    }
    
    // ok: kotlin-use-of-weak-rsa-key
    val keyPair = keyGenerator(3072)
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_13() {
    // Using a secure 2048-bit RSA key with RSAKeyGenParameterSpec and BigInteger exponent
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    val publicExponent = BigInteger.valueOf(65537)
    // ok: kotlin-use-of-weak-rsa-key
    keyPairGenerator.initialize(RSAKeyGenParameterSpec(2048, publicExponent))
    val keyPair = keyPairGenerator.generateKeyPair()
    
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_14() {
    // Using a secure RSA key with a when expression
    val securityLevel = "high"
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    
    val keySize = when (securityLevel) {
        "high" -> 4096
        "medium" -> 3072
        else -> 2048
    }
    
    // ok: kotlin-use-of-weak-rsa-key
    keyPairGenerator.initialize(keySize)
    val keyPair = keyPairGenerator.generateKeyPair()
    
    // Use the key for encryption
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_15() {
    // Using a secure 2048-bit RSA key from encoded key specs
    val keyFactory = KeyFactory.getInstance("RSA")
    
    // These would be the bytes of a 2048-bit key in practice
    val publicKeyBytes = ByteArray(256) // 2048 bits = 256 bytes
    val privateKeyBytes = ByteArray(256)
    
    // ok: kotlin-use-of-weak-rsa-key
    val publicKeySpec = X509EncodedKeySpec(publicKeyBytes)
    val privateKeySpec = PKCS8EncodedKeySpec(privateKeyBytes)
    
    try {
        val publicKey = keyFactory.generatePublic(publicKeySpec)
        val privateKey = keyFactory.generatePrivate(privateKeySpec)
        
        // Use the key for encryption
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encrypted = cipher.doFinal("Sensitive data".toByteArray())
    } catch (e: Exception) {
        // Handle exception in real code
        e.printStackTrace()
    }
}
// {/fact}