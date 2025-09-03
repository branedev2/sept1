import java.security.KeyPairGenerator
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import java.security.spec.ECGenParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.SecretKeyFactory
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.spec.InvalidKeySpecException
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.Base64
import java.security.SecureRandom

// True Positives (Vulnerable Code Examples)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_1() {
    // Initializing key generator and then re-initializing it after generation
    val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(128)
    val secretKey = keyGen.generateKey()
    
    // ruleid: kotlin-crypto-key-generator
    keyGen.init(128) // Unnecessary re-initialization
    val anotherKey = keyGen.generateKey()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_2() {
    // Using fixed seed for SecureRandom in key generator initialization
    val fixedSeed = "fixed_seed_value".toByteArray()
    val secureRandom = SecureRandom(fixedSeed)
    
    // ruleid: kotlin-crypto-key-generator
    val keyGen = KeyGenerator.getInstance("DES") // Weak algorithm
    keyGen.init(56, secureRandom) // Using predictable seed and weak key size
    val secretKey = keyGen.generateKey()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_3() {
    // Multiple initializations before key generation
    val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(128)
    
    // ruleid: kotlin-crypto-key-generator
    keyGen.init(192) // Overriding previous initialization
    keyGen.init(256) // Overriding again
    val secretKey = keyGen.generateKey()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_4() {
    // Using KeyPairGenerator with weak parameters and re-initialization
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(512) // Weak key size
    val keyPair = kpg.generateKeyPair()
    
    // ruleid: kotlin-crypto-key-generator
    kpg.initialize(512) // Unnecessary re-initialization with same weak parameters
    val anotherKeyPair = kpg.generateKeyPair()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_5() {
    // Using a non-random seed for SecureRandom
    val secureRandom = SecureRandom("static_seed".toByteArray())
    
    // ruleid: kotlin-crypto-key-generator
    val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(128, secureRandom) // Using predictable seed
    val secretKey = keyGen.generateKey()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_6() {
    // Initializing with default parameters and then re-initializing
    val keyGen = KeyGenerator.getInstance("AES")
    val secretKey = keyGen.generateKey() // Using default initialization
    
    // ruleid: kotlin-crypto-key-generator
    keyGen.init(128) // Unnecessary re-initialization after key generation
    val anotherKey = keyGen.generateKey()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_7() {
    // Using weak algorithm with re-initialization
    val keyGen = KeyGenerator.getInstance("RC4") // Weak algorithm
    keyGen.init(40) // Weak key size
    val secretKey = keyGen.generateKey()
    
    // ruleid: kotlin-crypto-key-generator
    keyGen.init(56) // Re-initialization with still weak key size
    val anotherKey = keyGen.generateKey()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_8() {
    // Using KeyPairGenerator with ECGenParameterSpec and re-initialization
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(ECGenParameterSpec("secp256r1"))
    val keyPair = kpg.generateKeyPair()
    
    // ruleid: kotlin-crypto-key-generator
    kpg.initialize(ECGenParameterSpec("secp256r1")) // Unnecessary re-initialization
    val anotherKeyPair = kpg.generateKeyPair()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_9() {
    try {
        // Using SecretKeyFactory with weak parameters and re-initialization
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        val spec = PBEKeySpec("password".toCharArray(), "salt".toByteArray(), 1000, 128) // Weak iteration count
        val tmp = factory.generateSecret(spec)
        
        // ruleid: kotlin-crypto-key-generator
        val spec2 = PBEKeySpec("password".toCharArray(), "salt".toByteArray(), 1000, 128)
        factory.generateSecret(spec2) // Generating another key with same weak parameters
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_10() {
    // Using KeyPairGenerator with RSAKeyGenParameterSpec and re-initialization
    val kpg = KeyPairGenerator.getInstance("RSA")
    val spec = RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4) // Weak key size
    kpg.initialize(spec)
    val keyPair = kpg.generateKeyPair()
    
    // ruleid: kotlin-crypto-key-generator
    kpg.initialize(spec) // Unnecessary re-initialization with same weak parameters
    val anotherKeyPair = kpg.generateKeyPair()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_11() {
    // Using KeyGenerator with provider and re-initialization
    val keyGen = KeyGenerator.getInstance("AES", "SunJCE")
    keyGen.init(128)
    val secretKey = keyGen.generateKey()
    
    // ruleid: kotlin-crypto-key-generator
    keyGen.init(128) // Unnecessary re-initialization
    val anotherKey = keyGen.generateKey()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_12() {
    // Using SecureRandom with predictable seed and re-initialization
    val secureRandom = SecureRandom()
    secureRandom.setSeed(123456L) // Predictable seed
    
    // ruleid: kotlin-crypto-key-generator
    val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(128, secureRandom)
    val secretKey = keyGen.generateKey()
    
    secureRandom.setSeed(123456L) // Re-seeding with same predictable value
    keyGen.init(128, secureRandom) // Re-initialization with predictable random
    val anotherKey = keyGen.generateKey()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_13() {
    // Using KeyGenerator with multiple re-initializations in a loop
    val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(128)
    
    for (i in 1..5) {
        // ruleid: kotlin-crypto-key-generator
        keyGen.init(128) // Unnecessary re-initialization in each loop iteration
        val key = keyGen.generateKey()
        println("Generated key $i")
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_14() {
    // Using KeyPairGenerator with conditional re-initialization
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(2048)
    val keyPair1 = kpg.generateKeyPair()
    
    val condition = true
    if (condition) {
        // ruleid: kotlin-crypto-key-generator
        kpg.initialize(2048) // Unnecessary conditional re-initialization
        val keyPair2 = kpg.generateKeyPair()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_15() {
    // Using KeyGenerator with try-catch and re-initialization
    try {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256)
        val secretKey = keyGen.generateKey()
        
        try {
            // Some operation that might fail
            // ruleid: kotlin-crypto-key-generator
            keyGen.init(256) // Unnecessary re-initialization in error handling
            val fallbackKey = keyGen.generateKey()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    } catch (e: NoSuchAlgorithmException) {
        e.printStackTrace()
    }
}
// {/fact}

// True Negatives (Secure Code Examples)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_1() {
    // Properly using KeyGenerator without re-initialization
    // ok: kotlin-crypto-key-generator
    val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(256) // Strong key size
    val secretKey = keyGen.generateKey()
    
    // Generate multiple keys without re-initializing
    val anotherKey = keyGen.generateKey()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_2() {
    // Using SecureRandom properly with KeyGenerator
    val secureRandom = SecureRandom()
    
    // ok: kotlin-crypto-key-generator
    val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(256, secureRandom) // Strong key size with proper random
    val secretKey = keyGen.generateKey()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_3() {
    // Using KeyPairGenerator properly
    // ok: kotlin-crypto-key-generator
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(2048) // Strong key size
    val keyPair = kpg.generateKeyPair()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_4() {
    // Using different KeyGenerator instances for different keys
    // ok: kotlin-crypto-key-generator
    val keyGen1 = KeyGenerator.getInstance("AES")
    keyGen1.init(256)
    val secretKey1 = keyGen1.generateKey()
    
    val keyGen2 = KeyGenerator.getInstance("AES")
    keyGen2.init(192)
    val secretKey2 = keyGen2.generateKey()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_5() {
    try {
        // Using SecretKeyFactory properly with strong parameters
        // ok: kotlin-crypto-key-generator
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec("strong_password".toCharArray(), 
                              SecureRandom().generateSeed(16), 
                              10000, // Strong iteration count
                              256)   // Strong key size
        val secretKey = factory.generateSecret(spec)
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_6() {
    // Using KeyPairGenerator with ECGenParameterSpec properly
    // ok: kotlin-crypto-key-generator
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(ECGenParameterSpec("secp256r1"))
    val keyPair = kpg.generateKeyPair()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_7() {
    // Using KeyGenerator in a loop without re-initialization
    // ok: kotlin-crypto-key-generator
    val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(256)
    
    val keys = ArrayList<javax.crypto.SecretKey>()
    for (i in 1..5) {
        keys.add(keyGen.generateKey()) // Generating multiple keys without re-initializing
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_8() {
    // Using different algorithms with separate initializations
    // ok: kotlin-crypto-key-generator
    val aesKeyGen = KeyGenerator.getInstance("AES")
    aesKeyGen.init(256)
    val aesKey = aesKeyGen.generateKey()
    
    val hmacKeyGen = KeyGenerator.getInstance("HmacSHA256")
    hmacKeyGen.init(256)
    val hmacKey = hmacKeyGen.generateKey()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_9() {
    try {
        // Using SecretKeyFactory for PBKDF2 properly
        // ok: kotlin-crypto-key-generator
        val salt = ByteArray(16)
        SecureRandom().nextBytes(salt)
        
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec("password".toCharArray(), salt, 65536, 256)
        val tmp = factory.generateSecret(spec)
        val secretKey = SecretKeySpec(tmp.encoded, "AES")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_10() {
    // Using KeyPairGenerator with RSAKeyGenParameterSpec properly
    // ok: kotlin-crypto-key-generator
    val kpg = KeyPairGenerator.getInstance("RSA")
    val spec = RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)
    kpg.initialize(spec)
    val keyPair = kpg.generateKeyPair()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_11() {
    // Using KeyGenerator with provider properly
    // ok: kotlin-crypto-key-generator
    try {
        val keyGen = KeyGenerator.getInstance("AES", "SunJCE")
        keyGen.init(256)
        val secretKey = keyGen.generateKey()
    } catch (e: NoSuchProviderException) {
        // Fallback to default provider
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256)
        val secretKey = keyGen.generateKey()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_12() {
    // Using SecureRandom properly without predictable seeding
    // ok: kotlin-crypto-key-generator
    val secureRandom = SecureRandom()
    // Not calling setSeed with a fixed value
    
    val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(256, secureRandom)
    val secretKey = keyGen.generateKey()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_13() {
    // Using conditional initialization only once before generating keys
    val useStrongerKey = true
    
    // ok: kotlin-crypto-key-generator
    val keyGen = KeyGenerator.getInstance("AES")
    if (useStrongerKey) {
        keyGen.init(256)
    } else {
        keyGen.init(192)
    }
    
    val secretKey = keyGen.generateKey()
    val anotherKey = keyGen.generateKey() // Generating another key without re-initializing
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_14() {
    // Using KeyGenerator with try-catch properly
    try {
        // ok: kotlin-crypto-key-generator
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256)
        val secretKey = keyGen.generateKey()
        
        // Some operation that might fail
        // No re-initialization here
        val anotherKey = keyGen.generateKey()
    } catch (e: NoSuchAlgorithmException) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_15() {
    // Using different KeyGenerator instances for different configurations
    // ok: kotlin-crypto-key-generator
    val standardKeyGen = KeyGenerator.getInstance("AES")
    standardKeyGen.init(256)
    val standardKey = standardKeyGen.generateKey()
    
    // Creating a new instance for a different configuration instead of re-initializing
    val customKeyGen = KeyGenerator.getInstance("AES")
    val secureRandom = SecureRandom()
    customKeyGen.init(192, secureRandom)
    val customKey = customKeyGen.generateKey()
}
// {/fact}