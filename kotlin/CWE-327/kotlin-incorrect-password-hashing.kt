import java.security.MessageDigest
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import java.security.SecureRandom
import java.util.Base64
import java.nio.charset.StandardCharsets
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder
import org.mindrot.jbcrypt.BCrypt

// True Positive Examples (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_1() {
    val password = "userPassword123"
    val md = MessageDigest.getInstance("SHA-256")
    // ruleid: kotlin-incorrect-password-hashing
    val hashedPassword = md.digest(password.toByteArray())
    val hexString = StringBuilder()
    for (b in hashedPassword) {
        hexString.append(String.format("%02x", b))
    }
    println("Hashed password: $hexString")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_2() {
    val userService = UserService()
    val password = "securePassword456"
    val md = MessageDigest.getInstance("MD5")
    // ruleid: kotlin-incorrect-password-hashing
    val hashedBytes = md.digest(password.toByteArray(StandardCharsets.UTF_8))
    val hashedPassword = Base64.getEncoder().encodeToString(hashedBytes)
    userService.saveUser("username", hashedPassword)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_3() {
    val password = "myP@ssw0rd"
    val username = "john_doe"
    
    // Adding username as salt (still insecure)
    val saltedPassword = username + password
    val md = MessageDigest.getInstance("SHA-1")
    // ruleid: kotlin-incorrect-password-hashing
    val digest = md.digest(saltedPassword.toByteArray())
    
    val hashedPassword = digest.joinToString("") { "%02x".format(it) }
    storeInDatabase(username, hashedPassword)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_4() {
    class PasswordHasher {
        fun hashPassword(password: String): String {
            val md = MessageDigest.getInstance("SHA-512")
            // ruleid: kotlin-incorrect-password-hashing
            val bytes = md.digest(password.toByteArray())
            return bytes.fold("") { str, it -> str + "%02x".format(it) }
        }
    }
    
    val hasher = PasswordHasher()
    val hashedPassword = hasher.hashPassword("userInput123")
    println("Storing hash: $hashedPassword")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_5() {
    val password = "testPassword"
    val salt = "staticSalt123" // Static salt is also problematic
    val md = MessageDigest.getInstance("SHA-256")
    md.update(salt.toByteArray())
    // ruleid: kotlin-incorrect-password-hashing
    val hashedPassword = md.digest(password.toByteArray())
    val base64Hash = Base64.getEncoder().encodeToString(hashedPassword)
    saveToDatabase("user", base64Hash)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_6() {
    fun verifyPassword(storedHash: String, inputPassword: String): Boolean {
        val md = MessageDigest.getInstance("SHA-256")
        // ruleid: kotlin-incorrect-password-hashing
        val calculatedHash = md.digest(inputPassword.toByteArray())
        val calculatedHashString = calculatedHash.joinToString("") { "%02x".format(it) }
        return storedHash == calculatedHashString
    }
    
    val isValid = verifyPassword("storedHash", "userInputPassword")
    println("Password valid: $isValid")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_7() {
    class UserAuthenticator {
        private val messageDigest = MessageDigest.getInstance("SHA-384")
        
        fun createHash(password: String): String {
            // ruleid: kotlin-incorrect-password-hashing
            val hashBytes = messageDigest.digest(password.toByteArray())
            return Base64.getEncoder().encodeToString(hashBytes)
        }
    }
    
    val authenticator = UserAuthenticator()
    val hash = authenticator.createHash("password123")
    println("Created hash: $hash")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_8() {
    val password = "mySecretPassword"
    val iterations = 1000 // Even with iterations, MessageDigest is not suitable
    
    val md = MessageDigest.getInstance("SHA-256")
    var result = password.toByteArray()
    
    for (i in 0 until iterations) {
        // ruleid: kotlin-incorrect-password-hashing
        result = md.digest(result)
    }
    
    val finalHash = Base64.getEncoder().encodeToString(result)
    println("Final hash after $iterations iterations: $finalHash")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_9() {
    fun hashForStorage(username: String, password: String): String {
        val combined = "$username:$password" // Combining with username doesn't make it secure
        val md = MessageDigest.getInstance("SHA-512")
        // ruleid: kotlin-incorrect-password-hashing
        val hashBytes = md.digest(combined.toByteArray())
        return hashBytes.joinToString("") { "%02x".format(it) }
    }
    
    val storedValue = hashForStorage("alice", "alicePassword")
    println("Stored value: $storedValue")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_10() {
    class PasswordManager {
        private val algorithm = "SHA-256"
        
        fun generateHash(password: String): ByteArray {
            val md = MessageDigest.getInstance(algorithm)
            // ruleid: kotlin-incorrect-password-hashing
            return md.digest(password.toByteArray())
        }
    }
    
    val manager = PasswordManager()
    val hash = manager.generateHash("userPassword")
    println("Hash length: ${hash.size}")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_11() {
    val password = "adminPassword"
    val pepper = "staticPepperValue" // Static pepper
    
    val md = MessageDigest.getInstance("SHA-256")
    // ruleid: kotlin-incorrect-password-hashing
    val hash = md.digest((password + pepper).toByteArray())
    
    val hexString = hash.joinToString("") { "%02x".format(it) }
    println("Hashed with pepper: $hexString")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_12() {
    fun doubleHash(input: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        // First hash
        val firstHash = md.digest(input.toByteArray())
        // Second hash (still insecure)
        // ruleid: kotlin-incorrect-password-hashing
        val secondHash = md.digest(firstHash)
        
        return Base64.getEncoder().encodeToString(secondHash)
    }
    
    val result = doubleHash("myPassword")
    println("Double hashed: $result")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_13() {
    class LegacyAuthSystem {
        fun hashWithTimestamp(password: String): String {
            val timestamp = System.currentTimeMillis().toString()
            val md = MessageDigest.getInstance("SHA-1") // SHA-1 is especially weak
            val input = password + timestamp
            // ruleid: kotlin-incorrect-password-hashing
            val hashBytes = md.digest(input.toByteArray())
            
            return hashBytes.joinToString("") { "%02x".format(it) } + ":" + timestamp
        }
    }
    
    val auth = LegacyAuthSystem()
    val hashedValue = auth.hashWithTimestamp("password123")
    println("Hashed with timestamp: $hashedValue")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_14() {
    val password = "myPassword"
    val salt = ByteArray(16).apply { SecureRandom().nextBytes(this) }
    
    // Even with a secure random salt, MessageDigest is not suitable for passwords
    val md = MessageDigest.getInstance("SHA-256")
    md.update(salt)
    // ruleid: kotlin-incorrect-password-hashing
    val hashedPassword = md.digest(password.toByteArray())
    
    val saltBase64 = Base64.getEncoder().encodeToString(salt)
    val hashBase64 = Base64.getEncoder().encodeToString(hashedPassword)
    println("Salt: $saltBase64, Hash: $hashBase64")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_15() {
    object PasswordUtil {
        fun hash(password: String): String {
            val md = MessageDigest.getInstance("SHA-512")
            // ruleid: kotlin-incorrect-password-hashing
            val hashBytes = md.digest(password.toByteArray(StandardCharsets.UTF_8))
            return hashBytes.joinToString("") { byte -> "%02x".format(byte) }
        }
    }
    
    val hashedPassword = PasswordUtil.hash("userPassword")
    println("Hashed password: $hashedPassword")
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_1() {
    val password = "userPassword123"
    val salt = ByteArray(16).apply { SecureRandom().nextBytes(this) }
    
    // ok: kotlin-incorrect-password-hashing
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val spec = PBEKeySpec(password.toCharArray(), salt, 65536, 256)
    val hash = factory.generateSecret(spec).encoded
    
    val saltBase64 = Base64.getEncoder().encodeToString(salt)
    val hashBase64 = Base64.getEncoder().encodeToString(hash)
    println("Salt: $saltBase64, Hash: $hashBase64")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_2() {
    val password = "securePassword456"
    
    // ok: kotlin-incorrect-password-hashing
    val bcryptEncoder = BCryptPasswordEncoder(12)
    val hashedPassword = bcryptEncoder.encode(password)
    
    println("BCrypt hashed: $hashedPassword")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_3() {
    class PasswordHasher {
        private val secureRandom = SecureRandom()
        
        fun hashPassword(password: String): String {
            val salt = ByteArray(16)
            secureRandom.nextBytes(salt)
            
            // ok: kotlin-incorrect-password-hashing
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
            val spec = PBEKeySpec(password.toCharArray(), salt, 120000, 512)
            val hash = factory.generateSecret(spec).encoded
            
            val saltHex = salt.joinToString("") { "%02x".format(it) }
            val hashHex = hash.joinToString("") { "%02x".format(it) }
            
            return "$saltHex:$hashHex"
        }
    }
    
    val hasher = PasswordHasher()
    val secureHash = hasher.hashPassword("myPassword")
    println("Secure hash: $secureHash")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_4() {
    val password = "testPassword"
    
    // ok: kotlin-incorrect-password-hashing
    val argon2Encoder = Argon2PasswordEncoder(16, 32, 1, 65536, 10)
    val hashedPassword = argon2Encoder.encode(password)
    
    println("Argon2 hash: $hashedPassword")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_5() {
    class UserAuthenticator {
        private val encoder = BCryptPasswordEncoder()
        
        fun createHash(password: String): String {
            // ok: kotlin-incorrect-password-hashing
            return encoder.encode(password)
        }
        
        fun verifyPassword(storedHash: String, inputPassword: String): Boolean {
            return encoder.matches(inputPassword, storedHash)
        }
    }
    
    val authenticator = UserAuthenticator()
    val hash = authenticator.createHash("password123")
    val isValid = authenticator.verifyPassword(hash, "password123")
    println("Hash: $hash, Valid: $isValid")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_6() {
    val password = "mySecretPassword"
    
    // ok: kotlin-incorrect-password-hashing
    val scryptEncoder = SCryptPasswordEncoder()
    val hashedPassword = scryptEncoder.encode(password)
    
    println("SCrypt hash: $hashedPassword")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_7() {
    fun secureHash(password: String): String {
        // ok: kotlin-incorrect-password-hashing
        return BCrypt.hashpw(password, BCrypt.gensalt(12))
    }
    
    fun verifyPassword(storedHash: String, inputPassword: String): Boolean {
        return BCrypt.checkpw(inputPassword, storedHash)
    }
    
    val hash = secureHash("userPassword")
    val isValid = verifyPassword(hash, "userPassword")
    println("Hash: $hash, Valid: $isValid")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_8() {
    val password = "adminPassword"
    
    // ok: kotlin-incorrect-password-hashing
    val pbkdf2Encoder = Pbkdf2PasswordEncoder("", 16, 310000, 256)
    val hashedPassword = pbkdf2Encoder.encode(password)
    
    println("PBKDF2 hash: $hashedPassword")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_9() {
    class PasswordManager {
        private val encoder = BCryptPasswordEncoder(10)
        
        fun hashPassword(password: String): String {
            // ok: kotlin-incorrect-password-hashing
            return encoder.encode(password)
        }
        
        fun validatePassword(rawPassword: String, encodedPassword: String): Boolean {
            return encoder.matches(rawPassword, encodedPassword)
        }
    }
    
    val manager = PasswordManager()
    val hash = manager.hashPassword("userPassword")
    println("BCrypt hash: $hash")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_10() {
    object SecurePasswordUtil {
        private val secureRandom = SecureRandom()
        
        fun generateSecurePassword(password: String): Pair<String, String> {
            val salt = ByteArray(16)
            secureRandom.nextBytes(salt)
            
            // ok: kotlin-incorrect-password-hashing
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val spec = PBEKeySpec(password.toCharArray(), salt, 210000, 256)
            val hash = factory.generateSecret(spec).encoded
            
            return Pair(
                Base64.getEncoder().encodeToString(salt),
                Base64.getEncoder().encodeToString(hash)
            )
        }
    }
    
    val (salt, hash) = SecurePasswordUtil.generateSecurePassword("myPassword")
    println("Salt: $salt, Hash: $hash")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_11() {
    val password = "myPassword"
    
    // Using Argon2 with custom parameters
    // ok: kotlin-incorrect-password-hashing
    val argon2Encoder = Argon2PasswordEncoder(32, 64, 4, 65536, 3)
    val hashedPassword = argon2Encoder.encode(password)
    
    println("Argon2 hash with custom params: $hashedPassword")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_12() {
    class ModernAuthSystem {
        private val bcryptEncoder = BCryptPasswordEncoder(12)
        
        fun register(username: String, password: String) {
            // ok: kotlin-incorrect-password-hashing
            val hashedPassword = bcryptEncoder.encode(password)
            saveToDatabase(username, hashedPassword)
        }
        
        fun authenticate(username: String, password: String): Boolean {
            val storedHash = getFromDatabase(username)
            return bcryptEncoder.matches(password, storedHash)
        }
    }
    
    val auth = ModernAuthSystem()
    auth.register("user1", "securePassword")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_13() {
    fun hashWithPBKDF2(password: String): String {
        val salt = ByteArray(16)
        SecureRandom().nextBytes(salt)
        
        // ok: kotlin-incorrect-password-hashing
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
        val spec = PBEKeySpec(password.toCharArray(), salt, 185000, 512)
        val hash = factory.generateSecret(spec).encoded
        
        val saltBase64 = Base64.getEncoder().encodeToString(salt)
        val hashBase64 = Base64.getEncoder().encodeToString(hash)
        
        return "$saltBase64:$hashBase64"
    }
    
    val secureHash = hashWithPBKDF2("userPassword")
    println("PBKDF2 hash: $secureHash")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_14() {
    val password = "testPassword"
    
    // Using SCrypt with custom parameters
    // ok: kotlin-incorrect-password-hashing
    val scryptEncoder = SCryptPasswordEncoder(16384, 8, 1, 32, 64)
    val hashedPassword = scryptEncoder.encode(password)
    
    println("SCrypt hash with custom params: $hashedPassword")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_15() {
    class SecurePasswordService {
        fun hashPassword(password: String): String {
            // ok: kotlin-incorrect-password-hashing
            return BCrypt.hashpw(password, BCrypt.gensalt(13))
        }
        
        fun verifyPassword(password: String, hashedPassword: String): Boolean {
            return BCrypt.checkpw(password, hashedPassword)
        }
    }
    
    val service = SecurePasswordService()
    val hash = service.hashPassword("mySecurePassword")
    val isValid = service.verifyPassword("mySecurePassword", hash)
    println("Hash: $hash, Valid: $isValid")
}
// {/fact}

// Helper functions to avoid compilation errors
fun storeInDatabase(username: String, hashedPassword: String) {
    // Implementation not relevant for the examples
}

fun saveToDatabase(username: String, hashedPassword: String) {
    // Implementation not relevant for the examples
}

fun getFromDatabase(username: String): String {
    // Implementation not relevant for the examples
    return "hashedPasswordFromDb"
}

class UserService {
    fun saveUser(username: String, hashedPassword: String) {
        // Implementation not relevant for the examples
    }
}