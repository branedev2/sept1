import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import java.security.MessageDigest
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

// True Positive Examples (Vulnerable Code)

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_1() {
    // Creating a new instance of BouncyCastleProvider each time a digest is needed
    val digest1 = MessageDigest.getInstance("SHA-256", 
        // ruleid: kotlin-improper-instantiation-of-bouncy-castle
        BouncyCastleProvider()
    )
    
    val data = "Test data".toByteArray()
    val hash1 = digest1.digest(data)
    
    // Creating another instance for the same purpose
    val digest2 = MessageDigest.getInstance("SHA-256", 
        // ruleid: kotlin-improper-instantiation-of-bouncy-castle
        BouncyCastleProvider()
    )
    
    val hash2 = digest2.digest(data)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_2() {
    // Creating multiple instances in a loop
    for (i in 1..10) {
        // ruleid: kotlin-improper-instantiation-of-bouncy-castle
        val provider = BouncyCastleProvider()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding", provider)
        // Do some encryption work
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_3() {
    class CryptoHelper {
        fun encrypt(data: ByteArray): ByteArray {
            // ruleid: kotlin-improper-instantiation-of-bouncy-castle
            val provider = BouncyCastleProvider()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding", provider)
            // Encryption logic
            return data // Simplified for example
        }
        
        fun decrypt(data: ByteArray): ByteArray {
            // ruleid: kotlin-improper-instantiation-of-bouncy-castle
            val provider = BouncyCastleProvider()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding", provider)
            // Decryption logic
            return data // Simplified for example
        }
    }
    
    val helper = CryptoHelper()
    helper.encrypt("secret".toByteArray())
    helper.decrypt("encrypted".toByteArray())
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_4() {
    // Creating provider instances in different methods
    fun generateKeyPair() {
        // ruleid: kotlin-improper-instantiation-of-bouncy-castle
        val provider = BouncyCastleProvider()
        val keyGen = KeyPairGenerator.getInstance("RSA", provider)
        keyGen.initialize(2048)
        val keyPair = keyGen.generateKeyPair()
    }
    
    fun signData(data: ByteArray) {
        // ruleid: kotlin-improper-instantiation-of-bouncy-castle
        val provider = BouncyCastleProvider()
        val signature = Signature.getInstance("SHA256withRSA", provider)
        // Signing logic
    }
    
    generateKeyPair()
    signData("data".toByteArray())
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_5() {
    // Creating provider in a multi-threaded environment
    val executor = Executors.newFixedThreadPool(5)
    
    for (i in 1..5) {
        executor.submit {
            // ruleid: kotlin-improper-instantiation-of-bouncy-castle
            val provider = BouncyCastleProvider()
            val digest = MessageDigest.getInstance("SHA-512", provider)
            // Hash some data
        }
    }
    
    executor.shutdown()
    executor.awaitTermination(10, TimeUnit.SECONDS)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_6() {
    // Creating provider instances in a recursive function
    fun processLevel(level: Int) {
        if (level <= 0) return
        
        // ruleid: kotlin-improper-instantiation-of-bouncy-castle
        val provider = BouncyCastleProvider()
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", provider)
        // Do some work
        
        processLevel(level - 1)
    }
    
    processLevel(3)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_7() {
    // Creating provider in a conditional block
    val useStrongCrypto = true
    
    if (useStrongCrypto) {
        // ruleid: kotlin-improper-instantiation-of-bouncy-castle
        val provider = BouncyCastleProvider()
        val keyGen = KeyGenerator.getInstance("AES", provider)
        keyGen.init(256)
        val key = keyGen.generateKey()
    } else {
        // Standard provider
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(128)
        val key = keyGen.generateKey()
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_8() {
    // Creating provider in a try-catch block
    try {
        // ruleid: kotlin-improper-instantiation-of-bouncy-castle
        val provider = BouncyCastleProvider()
        val mac = Mac.getInstance("HmacSHA256", provider)
        // Use MAC
    } catch (e: Exception) {
        // Fallback
        val mac = Mac.getInstance("HmacSHA256")
        // Use standard provider
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_9() {
    // Creating provider in a class constructor
    class SecureStorage {
        private val cipher: Cipher
        
        init {
            // ruleid: kotlin-improper-instantiation-of-bouncy-castle
            val provider = BouncyCastleProvider()
            cipher = Cipher.getInstance("AES/GCM/NoPadding", provider)
        }
        
        fun store(data: ByteArray) {
            // Store encrypted data
        }
    }
    
    val storage1 = SecureStorage()
    val storage2 = SecureStorage()
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_10() {
    // Creating multiple providers with different configurations
    // ruleid: kotlin-improper-instantiation-of-bouncy-castle
    val provider1 = BouncyCastleProvider()
    val keyStore1 = KeyStore.getInstance("PKCS12", provider1)
    
    // ruleid: kotlin-improper-instantiation-of-bouncy-castle
    val provider2 = BouncyCastleProvider()
    val keyStore2 = KeyStore.getInstance("BKS", provider2)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_11() {
    // Creating provider in a lambda
    val cryptoOperation = { input: ByteArray ->
        // ruleid: kotlin-improper-instantiation-of-bouncy-castle
        val provider = BouncyCastleProvider()
        val digest = MessageDigest.getInstance("SHA3-256", provider)
        digest.digest(input)
    }
    
    cryptoOperation("secret".toByteArray())
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_12() {
    // Creating provider in different scopes
    run {
        // ruleid: kotlin-improper-instantiation-of-bouncy-castle
        val provider = BouncyCastleProvider()
        val random = SecureRandom.getInstance("DEFAULT", provider)
        // Use random
    }
    
    run {
        // ruleid: kotlin-improper-instantiation-of-bouncy-castle
        val provider = BouncyCastleProvider()
        val random = SecureRandom.getInstance("DEFAULT", provider)
        // Use random again
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_13() {
    // Creating provider in a higher-order function
    fun withProvider(operation: (provider: BouncyCastleProvider) -> Unit) {
        // ruleid: kotlin-improper-instantiation-of-bouncy-castle
        val provider = BouncyCastleProvider()
        operation(provider)
    }
    
    withProvider { provider ->
        val cipher = Cipher.getInstance("AES/GCM/NoPadding", provider)
        // Use cipher
    }
    
    withProvider { provider ->
        val signature = Signature.getInstance("SHA512withRSA", provider)
        // Use signature
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_14() {
    // Creating provider in a when expression
    val algorithm = "RSA"
    
    when (algorithm) {
        "RSA" -> {
            // ruleid: kotlin-improper-instantiation-of-bouncy-castle
            val provider = BouncyCastleProvider()
            val keyGen = KeyPairGenerator.getInstance(algorithm, provider)
            // Generate keys
        }
        "EC" -> {
            // ruleid: kotlin-improper-instantiation-of-bouncy-castle
            val provider = BouncyCastleProvider()
            val keyGen = KeyPairGenerator.getInstance(algorithm, provider)
            // Generate keys
        }
        else -> {
            // Standard provider
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_15() {
    // Creating provider in a data processing pipeline
    val dataChunks = listOf("chunk1", "chunk2", "chunk3")
    
    val processedData = dataChunks.map { chunk ->
        // ruleid: kotlin-improper-instantiation-of-bouncy-castle
        val provider = BouncyCastleProvider()
        val digest = MessageDigest.getInstance("SHA-256", provider)
        digest.digest(chunk.toByteArray())
    }
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_1() {
    // ok: kotlin-improper-instantiation-of-bouncy-castle
    Security.addProvider(BouncyCastleProvider())
    
    val digest1 = MessageDigest.getInstance("SHA-256", "BC")
    val data = "Test data".toByteArray()
    val hash1 = digest1.digest(data)
    
    val digest2 = MessageDigest.getInstance("SHA-256", "BC")
    val hash2 = digest2.digest(data)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_2() {
    // ok: kotlin-improper-instantiation-of-bouncy-castle
    Security.addProvider(BouncyCastleProvider())
    
    for (i in 1..10) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC")
        // Do some encryption work
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_3() {
    class CryptoHelper {
        init {
            // ok: kotlin-improper-instantiation-of-bouncy-castle
            Security.addProvider(BouncyCastleProvider())
        }
        
        fun encrypt(data: ByteArray): ByteArray {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC")
            // Encryption logic
            return data // Simplified for example
        }
        
        fun decrypt(data: ByteArray): ByteArray {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC")
            // Decryption logic
            return data // Simplified for example
        }
    }
    
    val helper = CryptoHelper()
    helper.encrypt("secret".toByteArray())
    helper.decrypt("encrypted".toByteArray())
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_4() {
    // ok: kotlin-improper-instantiation-of-bouncy-castle
    Security.addProvider(BouncyCastleProvider())
    
    fun generateKeyPair() {
        val keyGen = KeyPairGenerator.getInstance("RSA", "BC")
        keyGen.initialize(2048)
        val keyPair = keyGen.generateKeyPair()
    }
    
    fun signData(data: ByteArray) {
        val signature = Signature.getInstance("SHA256withRSA", "BC")
        // Signing logic
    }
    
    generateKeyPair()
    signData("data".toByteArray())
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_5() {
    // ok: kotlin-improper-instantiation-of-bouncy-castle
    Security.addProvider(BouncyCastleProvider())
    
    val executor = Executors.newFixedThreadPool(5)
    
    for (i in 1..5) {
        executor.submit {
            val digest = MessageDigest.getInstance("SHA-512", "BC")
            // Hash some data
        }
    }
    
    executor.shutdown()
    executor.awaitTermination(10, TimeUnit.SECONDS)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_6() {
    // ok: kotlin-improper-instantiation-of-bouncy-castle
    val provider = BouncyCastleProvider()
    Security.addProvider(provider)
    
    fun processLevel(level: Int) {
        if (level <= 0) return
        
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC")
        // Do some work
        
        processLevel(level - 1)
    }
    
    processLevel(3)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_7() {
    // ok: kotlin-improper-instantiation-of-bouncy-castle
    Security.insertProviderAt(BouncyCastleProvider(), 1)
    
    val useStrongCrypto = true
    
    if (useStrongCrypto) {
        val keyGen = KeyGenerator.getInstance("AES", "BC")
        keyGen.init(256)
        val key = keyGen.generateKey()
    } else {
        // Standard provider
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(128)
        val key = keyGen.generateKey()
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_8() {
    // Using a singleton pattern for provider
    object BCProviderSingleton {
        val provider by lazy {
            // ok: kotlin-improper-instantiation-of-bouncy-castle
            BouncyCastleProvider().also {
                Security.addProvider(it)
            }
        }
    }
    
    val mac = Mac.getInstance("HmacSHA256", BCProviderSingleton.provider)
    // Use MAC
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_9() {
    // Using a companion object to manage provider
    class SecureStorage {
        companion object {
            init {
                // ok: kotlin-improper-instantiation-of-bouncy-castle
                Security.addProvider(BouncyCastleProvider())
            }
        }
        
        private val cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC")
        
        fun store(data: ByteArray) {
            // Store encrypted data
        }
    }
    
    val storage1 = SecureStorage()
    val storage2 = SecureStorage()
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_10() {
    // Using a single provider for multiple operations
    // ok: kotlin-improper-instantiation-of-bouncy-castle
    val provider = BouncyCastleProvider()
    Security.addProvider(provider)
    
    val keyStore1 = KeyStore.getInstance("PKCS12", "BC")
    val keyStore2 = KeyStore.getInstance("BKS", "BC")
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_11() {
    // Using a provider factory
    object ProviderFactory {
        init {
            // ok: kotlin-improper-instantiation-of-bouncy-castle
            Security.addProvider(BouncyCastleProvider())
        }
        
        fun getMessageDigest(algorithm: String) = MessageDigest.getInstance(algorithm, "BC")
    }
    
    val cryptoOperation = { input: ByteArray ->
        val digest = ProviderFactory.getMessageDigest("SHA3-256")
        digest.digest(input)
    }
    
    cryptoOperation("secret".toByteArray())
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_12() {
    // Adding provider once at application startup
    fun initializeSecurity() {
        // ok: kotlin-improper-instantiation-of-bouncy-castle
        Security.addProvider(BouncyCastleProvider())
    }
    
    initializeSecurity()
    
    run {
        val random = SecureRandom.getInstance("DEFAULT", "BC")
        // Use random
    }
    
    run {
        val random = SecureRandom.getInstance("DEFAULT", "BC")
        // Use random again
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_13() {
    // Using provider by name after adding it once
    // ok: kotlin-improper-instantiation-of-bouncy-castle
    Security.addProvider(BouncyCastleProvider())
    
    fun withCipher(operation: (cipher: Cipher) -> Unit) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC")
        operation(cipher)
    }
    
    withCipher { cipher ->
        // Use cipher
    }
    
    withCipher { cipher ->
        // Use cipher again
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_14() {
    // Adding provider once and using in when expression
    // ok: kotlin-improper-instantiation-of-bouncy-castle
    Security.addProvider(BouncyCastleProvider())
    
    val algorithm = "RSA"
    
    when (algorithm) {
        "RSA" -> {
            val keyGen = KeyPairGenerator.getInstance(algorithm, "BC")
            // Generate keys
        }
        "EC" -> {
            val keyGen = KeyPairGenerator.getInstance(algorithm, "BC")
            // Generate keys
        }
        else -> {
            // Standard provider
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_15() {
    // Adding provider once for data processing pipeline
    // ok: kotlin-improper-instantiation-of-bouncy-castle
    Security.addProvider(BouncyCastleProvider())
    
    val dataChunks = listOf("chunk1", "chunk2", "chunk3")
    
    val processedData = dataChunks.map { chunk ->
        val digest = MessageDigest.getInstance("SHA-256", "BC")
        digest.digest(chunk.toByteArray())
    }
}
// {/fact}