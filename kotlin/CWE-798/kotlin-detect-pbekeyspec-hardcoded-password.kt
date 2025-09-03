import java.security.spec.KeySpec
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import java.security.SecureRandom
import java.util.Properties
import java.io.FileInputStream
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec
import java.util.Base64
import java.io.File
import java.nio.charset.StandardCharsets
import kotlin.system.exitProcess
import java.io.InputStream
import java.io.FileOutputStream
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.URL
import java.net.HttpURLConnection
import javax.crypto.spec.PBEParameterSpec
import java.security.Key
import java.security.KeyStore
import kotlin.io.path.Path
import kotlin.io.path.inputStream
import kotlin.io.path.exists
import kotlin.io.path.createFile
import kotlin.io.path.outputStream
import kotlin.io.path.writeText
import kotlin.io.path.readText
import kotlin.io.path.deleteIfExists
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempFile
import kotlin.io.path.deleteExisting
import kotlin.io.path.deleteIfExists
import kotlin.io.path.createParentDirectories
import kotlin.io.path.absolutePathString
import kotlin.io.path.pathString
import kotlin.io.path.name
import kotlin.io.path.extension
import kotlin.io.path.nameWithoutExtension
import kotlin.io.path.div
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.isDirectory
import kotlin.io.path.isRegularFile
import kotlin.io.path.fileSize
import kotlin.io.path.getLastModifiedTime
import kotlin.io.path.isHidden
import kotlin.io.path.isReadable
import kotlin.io.path.isWritable
import kotlin.io.path.isExecutable
import kotlin.io.path.moveTo
import kotlin.io.path.copyTo
import kotlin.io.path.createSymbolicLinkPointingTo
import kotlin.io.path.readAttributes
import kotlin.io.path.setAttribute
import kotlin.io.path.getPosixFilePermissions
import kotlin.io.path.setPosixFilePermissions
import kotlin.io.path.fileAttributesView
import kotlin.io.path.readSymbolicLink
import kotlin.io.path.isSymbolicLink
import kotlin.io.path.isSameFileAs
import kotlin.io.path.toFile
import kotlin.io.path.toPath
import kotlin.io.path.useLines
import kotlin.io.path.reader
import kotlin.io.path.writer
import kotlin.io.path.bufferedReader
import kotlin.io.path.bufferedWriter
import kotlin.io.path.forEachLine
import kotlin.io.path.readLines
import kotlin.io.path.writeLines
import kotlin.io.path.appendLines
import kotlin.io.path.appendText
import kotlin.io.path.readBytes
import kotlin.io.path.writeBytes
import kotlin.io.path.appendBytes
import kotlin.io.path.inputStream
import kotlin.io.path.outputStream
import kotlin.io.path.bufferedInputStream
import kotlin.io.path.bufferedOutputStream
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.io.path.appendText
import kotlin.io.path.readLines
import kotlin.io.path.writeLines
import kotlin.io.path.appendLines
import kotlin.io.path.readBytes
import kotlin.io.path.writeBytes
import kotlin.io.path.appendBytes
import kotlin.io.path.inputStream
import kotlin.io.path.outputStream
import kotlin.io.path.bufferedInputStream
import kotlin.io.path.bufferedOutputStream
import kotlin.io.path.reader
import kotlin.io.path.writer
import kotlin.io.path.bufferedReader
import kotlin.io.path.bufferedWriter
import kotlin.io.path.forEachLine
import kotlin.io.path.useLines
import kotlin.io.path.createTempDirectory
import kotlin.io.path.createTempFile
import kotlin.io.path.createDirectories
import kotlin.io.path.createDirectory
import kotlin.io.path.createFile
import kotlin.io.path.deleteExisting
import kotlin.io.path.deleteIfExists
import kotlin.io.path.moveTo
import kotlin.io.path.copyTo
import kotlin.io.path.createSymbolicLinkPointingTo
import kotlin.io.path.readSymbolicLink
import kotlin.io.path.isSymbolicLink
import kotlin.io.path.isSameFileAs
import kotlin.io.path.toFile
import kotlin.io.path.toPath
import kotlin.io.path.absolutePathString
import kotlin.io.path.pathString
import kotlin.io.path.name
import kotlin.io.path.extension
import kotlin.io.path.nameWithoutExtension
import kotlin.io.path.div
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.isDirectory
import kotlin.io.path.isRegularFile
import kotlin.io.path.fileSize
import kotlin.io.path.getLastModifiedTime
import kotlin.io.path.isHidden
import kotlin.io.path.isReadable
import kotlin.io.path.isWritable
import kotlin.io.path.isExecutable
import kotlin.io.path.readAttributes
import kotlin.io.path.setAttribute
import kotlin.io.path.getPosixFilePermissions
import kotlin.io.path.setPosixFilePermissions
import kotlin.io.path.fileAttributesView
import kotlin.io.path.exists
import kotlin.io.path.notExists
import kotlin.io.path.isRegularFile
import kotlin.io.path.isDirectory
import kotlin.io.path.isSymbolicLink
import kotlin.io.path.isHidden
import kotlin.io.path.isReadable
import kotlin.io.path.isWritable
import kotlin.io.path.isExecutable
import kotlin.io.path.fileSize
import kotlin.io.path.getLastModifiedTime
import kotlin.io.path.readAttributes
import kotlin.io.path.setAttribute
import kotlin.io.path.getPosixFilePermissions
import kotlin.io.path.setPosixFilePermissions
import kotlin.io.path.fileAttributesView
import kotlin.io.path.isSameFileAs
import kotlin.io.path.toFile
import kotlin.io.path.toPath
import kotlin.io.path.absolutePathString
import kotlin.io.path.pathString
import kotlin.io.path.name
import kotlin.io.path.extension
import kotlin.io.path.nameWithoutExtension
import kotlin.io.path.div
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.createParentDirectories
import kotlin.io.path.createDirectories
import kotlin.io.path.createDirectory
import kotlin.io.path.createFile
import kotlin.io.path.createSymbolicLinkPointingTo
import kotlin.io.path.createTempDirectory
import kotlin.io.path.createTempFile
import kotlin.io.path.deleteExisting
import kotlin.io.path.deleteIfExists
import kotlin.io.path.moveTo
import kotlin.io.path.copyTo
import kotlin.io.path.readSymbolicLink
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.io.path.appendText
import kotlin.io.path.readLines
import kotlin.io.path.writeLines
import kotlin.io.path.appendLines
import kotlin.io.path.readBytes
import kotlin.io.path.writeBytes
import kotlin.io.path.appendBytes
import kotlin.io.path.inputStream
import kotlin.io.path.outputStream
import kotlin.io.path.bufferedInputStream
import kotlin.io.path.bufferedOutputStream
import kotlin.io.path.reader
import kotlin.io.path.writer
import kotlin.io.path.bufferedReader
import kotlin.io.path.bufferedWriter
import kotlin.io.path.forEachLine
import kotlin.io.path.useLines
import java.io.Console
import kotlin.system.getenv

// True Positives (Vulnerable Code Examples)

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_1() {
    val salt = ByteArray(16)
    SecureRandom().nextBytes(salt)
    val iterationCount = 10000
    
    // ruleid: kotlin-detect-pbekeyspec-hardcoded-password
    val keySpec = PBEKeySpec("password123".toCharArray(), salt, iterationCount, 256)
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val key = factory.generateSecret(keySpec)
    
    // Use the key for encryption
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key.encoded, "AES"))
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_2() {
    val salt = "randomsalt".toByteArray()
    val iterations = 1000
    
    // ruleid: kotlin-detect-pbekeyspec-hardcoded-password
    val pbeKeySpec = PBEKeySpec("mySecretPassword".toCharArray(), salt, iterations, 128)
    val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
    val secretKey = secretKeyFactory.generateSecret(pbeKeySpec)
    
    println("Key generated: ${Base64.getEncoder().encodeToString(secretKey.encoded)}")
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_3() {
    fun encryptData(data: String): String {
        val salt = ByteArray(8)
        SecureRandom().nextBytes(salt)
        
        // ruleid: kotlin-detect-pbekeyspec-hardcoded-password
        val pbeKeySpec = PBEKeySpec("hardcoded_pwd_123!".toCharArray(), salt, 1000, 128)
        val secretKeyFactory = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128")
        val key = secretKeyFactory.generateSecret(pbeKeySpec)
        
        // Encryption logic
        return "encrypted_" + data
    }
    
    val sensitiveData = "Personal Information"
    val encrypted = encryptData(sensitiveData)
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_4() {
    class EncryptionService {
        private val hardcodedPassword = "S3cureP@ssw0rd!"
        
        fun generateKey(salt: ByteArray): SecretKey {
            // ruleid: kotlin-detect-pbekeyspec-hardcoded-password
            val pbeKeySpec = PBEKeySpec(hardcodedPassword.toCharArray(), salt, 10000, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            return SecretKeySpec(factory.generateSecret(pbeKeySpec).encoded, "AES")
        }
    }
    
    val service = EncryptionService()
    val salt = ByteArray(16).apply { SecureRandom().nextBytes(this) }
    val key = service.generateKey(salt)
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_5() {
    val databasePassword = "db_password_2023"
    val salt = "database_salt".toByteArray()
    
    // ruleid: kotlin-detect-pbekeyspec-hardcoded-password
    val keySpec = PBEKeySpec(databasePassword.toCharArray(), salt, 5000, 256)
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val secretKey = factory.generateSecret(keySpec)
    
    println("Database encryption key generated")
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_6() {
    object CryptoUtils {
        fun createEncryptionKey(): SecretKey {
            val salt = "static_salt_value".toByteArray()
            
            // ruleid: kotlin-detect-pbekeyspec-hardcoded-password
            val pbeSpec = PBEKeySpec("APIKey#2023".toCharArray(), salt, 10000, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            return SecretKeySpec(factory.generateSecret(pbeSpec).encoded, "AES")
        }
    }
    
    val key = CryptoUtils.createEncryptionKey()
    // Use key for API authentication
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_7() {
    val configPassword = "config_password_123"
    
    fun initializeEncryption(): Cipher {
        val salt = ByteArray(16)
        SecureRandom().nextBytes(salt)
        
        // ruleid: kotlin-detect-pbekeyspec-hardcoded-password
        val pbeKeySpec = PBEKeySpec(configPassword.toCharArray(), salt, 1000, 128)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        val tmp = factory.generateSecret(pbeKeySpec)
        val secretKey = SecretKeySpec(tmp.encoded, "AES")
        
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val iv = ByteArray(16)
        SecureRandom().nextBytes(iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, IvParameterSpec(iv))
        return cipher
    }
    
    val cipher = initializeEncryption()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_8() {
    class FileEncryptor {
        private val password = "FileEncryptorPass!"
        
        fun encrypt(data: ByteArray): ByteArray {
            val salt = ByteArray(8)
            SecureRandom().nextBytes(salt)
            
            // ruleid: kotlin-detect-pbekeyspec-hardcoded-password
            val keySpec = PBEKeySpec(password.toCharArray(), salt, 10000, 128)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
            val tmp = factory.generateSecret(keySpec)
            val secretKey = SecretKeySpec(tmp.encoded, "AES")
            
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            return cipher.doFinal(data)
        }
    }
    
    val encryptor = FileEncryptor()
    val encrypted = encryptor.encrypt("sensitive data".toByteArray())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_9() {
    val MASTER_PASSWORD = "MasterKey2023!"
    
    fun deriveKeyFromPassword(): SecretKey {
        val salt = "fixed_salt_value".toByteArray()
        
        // ruleid: kotlin-detect-pbekeyspec-hardcoded-password
        val keySpec = PBEKeySpec(MASTER_PASSWORD.toCharArray(), salt, 20000, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return SecretKeySpec(factory.generateSecret(keySpec).encoded, "AES")
    }
    
    val key = deriveKeyFromPassword()
    println("Master key derived successfully")
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_10() {
    class CloudStorageEncryption {
        fun encryptForStorage(data: String): String {
            val salt = ByteArray(16)
            SecureRandom().nextBytes(salt)
            
            // ruleid: kotlin-detect-pbekeyspec-hardcoded-password
            val pbeKeySpec = PBEKeySpec("CloudStorage#Key".toCharArray(), salt, 15000, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val secretKey = factory.generateSecret(pbeKeySpec)
            
            // Encryption logic
            return "encrypted_$data"
        }
    }
    
    val cloudStorage = CloudStorageEncryption()
    val encryptedData = cloudStorage.encryptForStorage("cloud backup data")
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_11() {
    val appId = "app_12345"
    val appSecret = "app_secret_67890"
    
    fun generateAppKey(): SecretKey {
        // ruleid: kotlin-detect-pbekeyspec-hardcoded-password
        val keySpec = PBEKeySpec("$appId:$appSecret".toCharArray(), 
                                "application_salt".toByteArray(), 
                                10000, 
                                256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return SecretKeySpec(factory.generateSecret(keySpec).encoded, "AES")
    }
    
    val appKey = generateAppKey()
    println("Application key generated")
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_12() {
    object TokenGenerator {
        private val tokenPassword = "t0k3n_g3n3r@t0r"
        
        fun generateToken(userId: String): String {
            val salt = userId.toByteArray()
            
            // ruleid: kotlin-detect-pbekeyspec-hardcoded-password
            val keySpec = PBEKeySpec(tokenPassword.toCharArray(), salt, 5000, 128)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
            val key = factory.generateSecret(keySpec)
            
            // Token generation logic
            return "token_${Base64.getEncoder().encodeToString(key.encoded)}"
        }
    }
    
    val userToken = TokenGenerator.generateToken("user123")
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_13() {
    class BackupEncryption {
        private val backupKey = "B@ckup_K3y_2023"
        
        fun encryptBackup(data: ByteArray): ByteArray {
            val salt = "backup_salt".toByteArray()
            
            // ruleid: kotlin-detect-pbekeyspec-hardcoded-password
            val pbeKeySpec = PBEKeySpec(backupKey.toCharArray(), salt, 10000, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val secretKey = SecretKeySpec(factory.generateSecret(pbeKeySpec).encoded, "AES")
            
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            return cipher.doFinal(data)
        }
    }
    
    val backupService = BackupEncryption()
    val encryptedBackup = backupService.encryptBackup("important data".toByteArray())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_14() {
    fun createEncryptedConnection(): String {
        val connectionPassword = "c0nn3ct10n_p@ss"
        val salt = ByteArray(16)
        SecureRandom().nextBytes(salt)
        
        // ruleid: kotlin-detect-pbekeyspec-hardcoded-password
        val keySpec = PBEKeySpec(connectionPassword.toCharArray(), salt, 12000, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val secretKey = factory.generateSecret(keySpec)
        
        // Connection establishment logic
        return "secure_connection_established"
    }
    
    val connection = createEncryptedConnection()
    println(connection)
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_15() {
    class SecureMessaging {
        private val messageKey = "M3ss@g1ng_K3y!"
        
        fun encryptMessage(message: String): String {
            val salt = ByteArray(8)
            SecureRandom().nextBytes(salt)
            
            // ruleid: kotlin-detect-pbekeyspec-hardcoded-password
            val pbeKeySpec = PBEKeySpec(messageKey.toCharArray(), salt, 8000, 128)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
            val key = factory.generateSecret(pbeKeySpec)
            
            // Message encryption logic
            return "encrypted_${message.length}_chars"
        }
    }
    
    val messaging = SecureMessaging()
    val encryptedMessage = messaging.encryptMessage("Hello, this is a secure message")
}
// {/fact}

// True Negatives (Secure Code Examples)

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_1() {
    fun getPasswordFromUser(): CharArray {
        // In a real application, this would prompt the user for a password
        // For this example, we'll simulate user input
        return "user_input_password".toCharArray()
    }
    
    val salt = ByteArray(16)
    SecureRandom().nextBytes(salt)
    val iterationCount = 10000
    
    // ok: kotlin-detect-pbekeyspec-hardcoded-password
    val keySpec = PBEKeySpec(getPasswordFromUser(), salt, iterationCount, 256)
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val key = factory.generateSecret(keySpec)
    
    // Use the key for encryption
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key.encoded, "AES"))
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_2() {
    val salt = "randomsalt".toByteArray()
    val iterations = 1000
    
    // Read password from environment variable
    val envPassword = System.getenv("APP_PASSWORD") ?: throw IllegalStateException("Password not set in environment")
    
    // ok: kotlin-detect-pbekeyspec-hardcoded-password
    val pbeKeySpec = PBEKeySpec(envPassword.toCharArray(), salt, iterations, 128)
    val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
    val secretKey = secretKeyFactory.generateSecret(pbeKeySpec)
    
    println("Key generated: ${Base64.getEncoder().encodeToString(secretKey.encoded)}")
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_3() {
    fun encryptData(data: String, password: CharArray): String {
        val salt = ByteArray(8)
        SecureRandom().nextBytes(salt)
        
        // ok: kotlin-detect-pbekeyspec-hardcoded-password
        val pbeKeySpec = PBEKeySpec(password, salt, 1000, 128)
        val secretKeyFactory = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128")
        val key = secretKeyFactory.generateSecret(pbeKeySpec)
        
        // Encryption logic
        return "encrypted_" + data
    }
    
    val sensitiveData = "Personal Information"
    // Password provided by user or external system
    val userPassword = readLine()?.toCharArray() ?: CharArray(0)
    val encrypted = encryptData(sensitiveData, userPassword)
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_4() {
    class EncryptionService {
        fun generateKey(password: CharArray, salt: ByteArray): SecretKey {
            // ok: kotlin-detect-pbekeyspec-hardcoded-password
            val pbeKeySpec = PBEKeySpec(password, salt, 10000, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            return SecretKeySpec(factory.generateSecret(pbeKeySpec).encoded, "AES")
        }
    }
    
    val service = EncryptionService()
    val salt = ByteArray(16).apply { SecureRandom().nextBytes(this) }
    
    // Password retrieved from secure storage or user input
    val passwordFromSecureStorage = System.getenv("SECURE_PASSWORD")?.toCharArray() 
                                   ?: "fallback".toCharArray()
    val key = service.generateKey(passwordFromSecureStorage, salt)
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_5() {
    // Load password from properties file
    fun loadDatabasePassword(): String {
        val properties = Properties()
        val inputStream = FileInputStream("config.properties")
        properties.load(inputStream)
        return properties.getProperty("db.password")
    }
    
    val databasePassword = loadDatabasePassword()
    val salt = "database_salt".toByteArray()
    
    // ok: kotlin-detect-pbekeyspec-hardcoded-password
    val keySpec = PBEKeySpec(databasePassword.toCharArray(), salt, 5000, 256)
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val secretKey = factory.generateSecret(keySpec)
    
    println("Database encryption key generated")
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_6() {
    object CryptoUtils {
        fun createEncryptionKey(apiKeyPassword: CharArray): SecretKey {
            val salt = "static_salt_value".toByteArray()
            
            // ok: kotlin-detect-pbekeyspec-hardcoded-password
            val pbeSpec = PBEKeySpec(apiKeyPassword, salt, 10000, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            return SecretKeySpec(factory.generateSecret(pbeSpec).encoded, "AES")
        }
    }
    
    // API key retrieved from secure storage
    val apiKey = System.getenv("API_KEY")?.toCharArray() ?: CharArray(0)
    val key = CryptoUtils.createEncryptionKey(apiKey)
    // Use key for API authentication
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_7() {
    // Password retrieved from a secure vault service
    fun getPasswordFromVault(): CharArray {
        // In a real application, this would connect to a vault service
        // For this example, we'll simulate vault retrieval
        return System.getenv("CONFIG_PASSWORD")?.toCharArray() ?: CharArray(0)
    }
    
    fun initializeEncryption(): Cipher {
        val salt = ByteArray(16)
        SecureRandom().nextBytes(salt)
        
        // ok: kotlin-detect-pbekeyspec-hardcoded-password
        val pbeKeySpec = PBEKeySpec(getPasswordFromVault(), salt, 1000, 128)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        val tmp = factory.generateSecret(pbeKeySpec)
        val secretKey = SecretKeySpec(tmp.encoded, "AES")
        
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val iv = ByteArray(16)
        SecureRandom().nextBytes(iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, IvParameterSpec(iv))
        return cipher
    }
    
    val cipher = initializeEncryption()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_8() {
    class FileEncryptor {
        fun encrypt(data: ByteArray, password: CharArray): ByteArray {
            val salt = ByteArray(8)
            SecureRandom().nextBytes(salt)
            
            // ok: kotlin-detect-pbekeyspec-hardcoded-password
            val keySpec = PBEKeySpec(password, salt, 10000, 128)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
            val tmp = factory.generateSecret(keySpec)
            val secretKey = SecretKeySpec(tmp.encoded, "AES")
            
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            return cipher.doFinal(data)
        }
    }
    
    val encryptor = FileEncryptor()
    // Password provided by user
    val userPassword = readLine()?.toCharArray() ?: CharArray(0)
    val encrypted = encryptor.encrypt("sensitive data".toByteArray(), userPassword)
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_9() {
    fun loadPasswordFromKeyStore(): CharArray {
        val keyStore = KeyStore.getInstance("PKCS12")
        val keyStoreFile = FileInputStream("keystore.p12")
        keyStore.load(keyStoreFile, "keystore_password".toCharArray())
        
        val secretEntry = keyStore.getEntry(
            "password_alias", 
            KeyStore.PasswordProtection("entry_password".toCharArray())
        ) as KeyStore.SecretKeyEntry
        
        return String(secretEntry.secretKey.encoded).toCharArray()
    }
    
    fun deriveKeyFromPassword(): SecretKey {
        val salt = "fixed_salt_value".toByteArray()
        
        // ok: kotlin-detect-pbekeyspec-hardcoded-password
        val keySpec = PBEKeySpec(loadPasswordFromKeyStore(), salt, 20000, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return SecretKeySpec(factory.generateSecret(keySpec).encoded, "AES")
    }
    
    val key = deriveKeyFromPassword()
    println("Master key derived successfully")
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_10() {
    class CloudStorageEncryption {
        fun encryptForStorage(data: String, password: CharArray): String {
            val salt = ByteArray(16)
            SecureRandom().nextBytes(salt)
            
            // ok: kotlin-detect-pbekeyspec-hardcoded-password
            val pbeKeySpec = PBEKeySpec(password, salt, 15000, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val secretKey = factory.generateSecret(pbeKeySpec)
            
            // Encryption logic
            return "encrypted_$data"
        }
    }
    
    val cloudStorage = CloudStorageEncryption()
    // Password retrieved from environment variable
    val storagePassword = System.getenv("STORAGE_PASSWORD")?.toCharArray() 
                         ?: throw IllegalStateException("Storage password not set")
    val encryptedData = cloudStorage.encryptForStorage("cloud backup data", storagePassword)
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_11() {
    // Load credentials from configuration file
    fun loadAppCredentials(): Pair<String, String> {
        val properties = Properties()
        properties.load(FileInputStream("app_config.properties"))
        val appId = properties.getProperty("app.id")
        val appSecret = properties.getProperty("app.secret")
        return Pair(appId, appSecret)
    }
    
    fun generateAppKey(): SecretKey {
        val (appId, appSecret) = loadAppCredentials()
        
        // ok: kotlin-detect-pbekeyspec-hardcoded-password
        val keySpec = PBEKeySpec("$appId:$appSecret".toCharArray(), 
                                "application_salt".toByteArray(), 
                                10000, 
                                256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return SecretKeySpec(factory.generateSecret(keySpec).encoded, "AES")
    }
    
    val appKey = generateAppKey()
    println("Application key generated")
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_12() {
    object TokenGenerator {
        // Get token password from secure storage
        private fun getTokenPassword(): CharArray {
            // In a real application, this would retrieve from secure storage
            return System.getenv("TOKEN_PASSWORD")?.toCharArray() 
                  ?: throw IllegalStateException("Token password not set")
        }
        
        fun generateToken(userId: String): String {
            val salt = userId.toByteArray()
            
            // ok: kotlin-detect-pbekeyspec-hardcoded-password
            val keySpec = PBEKeySpec(getTokenPassword(), salt, 5000, 128)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
            val key = factory.generateSecret(keySpec)
            
            // Token generation logic
            return "token_${Base64.getEncoder().encodeToString(key.encoded)}"
        }
    }
    
    val userToken = TokenGenerator.generateToken("user123")
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_13() {
    class BackupEncryption {
        // Get backup key from secure configuration
        private fun getBackupKey(): CharArray {
            val properties = Properties()
            properties.load(FileInputStream("backup_config.properties"))
            return properties.getProperty("backup.key").toCharArray()
        }
        
        fun encryptBackup(data: ByteArray): ByteArray {
            val salt = "backup_salt".toByteArray()
            
            // ok: kotlin-detect-pbekeyspec-hardcoded-password
            val pbeKeySpec = PBEKeySpec(getBackupKey(), salt, 10000, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val secretKey = SecretKeySpec(factory.generateSecret(pbeKeySpec).encoded, "AES")
            
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            return cipher.doFinal(data)
        }
    }
    
    val backupService = BackupEncryption()
    val encryptedBackup = backupService.encryptBackup("important data".toByteArray())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_14() {
    fun createEncryptedConnection(connectionPassword: CharArray): String {
        val salt = ByteArray(16)
        SecureRandom().nextBytes(salt)
        
        // ok: kotlin-detect-pbekeyspec-hardcoded-password
        val keySpec = PBEKeySpec(connectionPassword, salt, 12000, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val secretKey = factory.generateSecret(keySpec)
        
        // Connection establishment logic
        return "secure_connection_established"
    }
    
    // Password retrieved from environment or configuration
    val password = System.getenv("CONNECTION_PASSWORD")?.toCharArray() 
                  ?: throw IllegalStateException("Connection password not set")
    val connection = createEncryptedConnection(password)
    println(connection)
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_15() {
    class SecureMessaging {
        fun encryptMessage(message: String, password: CharArray): String {
            val salt = ByteArray(8)
            SecureRandom().nextBytes(salt)
            
            // ok: kotlin-detect-pbekeyspec-hardcoded-password
            val pbeKeySpec = PBEKeySpec(password, salt, 8000, 128)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
            val key = factory.generateSecret(pbeKeySpec)
            
            // Message encryption logic
            return "encrypted_${message.length}_chars"
        }
    }
    
    val messaging = SecureMessaging()
    
    // Password retrieved from user input or secure storage
    val messagePassword = readLine()?.toCharArray() ?: CharArray(0)
    val encryptedMessage = messaging.encryptMessage("Hello, this is a secure message", messagePassword)
}
// {/fact}