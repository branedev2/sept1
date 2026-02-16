import android.content.Context
import android.util.Log
import java.io.*
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore

// TRUE POSITIVES - Vulnerable code examples

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
fun bad_case_1(context: Context) {
    try {
        val fileName = "user_credentials.txt"
        val fileContents = "username=admin\npassword=secret123"
        
        // ruleid: kotlin-unencrypted-files-in-app
        val fileOutputStream = context.openFileOutput(fileName, Context.MODE_PRIVATE)
        fileOutputStream.write(fileContents.toByteArray())
        fileOutputStream.close()
        
        Log.d("FileStorage", "Saved user credentials to file")
    } catch (e: Exception) {
        Log.e("FileStorage", "Error saving credentials", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
fun bad_case_2(context: Context) {
    val sensitiveData = "Credit Card: 4111-1111-1111-1111, Exp: 12/25, CVV: 123"
    val file = File(context.filesDir, "payment_info.txt")
    
    try {
        // ruleid: kotlin-unencrypted-files-in-app
        val writer = FileWriter(file)
        writer.write(sensitiveData)
        writer.close()
        Log.d("PaymentInfo", "Saved payment information")
    } catch (e: Exception) {
        Log.e("PaymentInfo", "Failed to save payment info", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
fun bad_case_3(context: Context) {
    val userHealthData = "Patient: John Doe, Blood Type: O+, Conditions: Hypertension"
    
    try {
        // ruleid: kotlin-unencrypted-files-in-app
        val fos = FileOutputStream(File(context.filesDir, "health_records.txt"))
        fos.write(userHealthData.toByteArray())
        fos.close()
    } catch (e: Exception) {
        Log.e("HealthApp", "Failed to save health data", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
fun bad_case_4(context: Context) {
    val apiKeys = "API_KEY=abc123def456\nSECRET_KEY=xyz789uvw"
    
    try {
        // ruleid: kotlin-unencrypted-files-in-app
        val outputStream = context.openFileOutput("api_keys.properties", Context.MODE_PRIVATE)
        outputStream.use { 
            it.write(apiKeys.toByteArray())
        }
        Log.d("APIConfig", "API keys saved to local storage")
    } catch (e: Exception) {
        Log.e("APIConfig", "Failed to save API keys", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
fun bad_case_5() {
    val personalNotes = "Remember to call therapist about anxiety issues"
    
    try {
        val file = File("/data/data/com.example.app/files/notes.txt")
        // ruleid: kotlin-unencrypted-files-in-app
        val outputStream = FileOutputStream(file)
        outputStream.write(personalNotes.toByteArray())
        outputStream.close()
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
fun bad_case_6(context: Context) {
    val loginSession = "session_token=a1b2c3d4e5f6g7h8i9j0"
    
    try {
        // ruleid: kotlin-unencrypted-files-in-app
        val writer = BufferedWriter(FileWriter(File(context.filesDir, "session.dat")))
        writer.write(loginSession)
        writer.close()
    } catch (e: Exception) {
        Log.e("Session", "Failed to save session data", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
fun bad_case_7(context: Context) {
    val locationHistory = "Home: 37.7749° N, 122.4194° W\nWork: 37.3861° N, 122.0839° W"
    
    try {
        // ruleid: kotlin-unencrypted-files-in-app
        val fos = context.openFileOutput("location_history.txt", Context.MODE_PRIVATE)
        val oos = ObjectOutputStream(fos)
        oos.writeObject(locationHistory)
        oos.close()
        fos.close()
    } catch (e: Exception) {
        Log.e("LocationTracker", "Failed to save location history", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
fun bad_case_8(context: Context) {
    val contactsList = "John Doe: 555-1234\nJane Smith: 555-5678"
    val file = File(context.getExternalFilesDir(null), "contacts.txt")
    
    try {
        // ruleid: kotlin-unencrypted-files-in-app
        val fos = FileOutputStream(file)
        fos.write(contactsList.toByteArray())
        fos.close()
    } catch (e: Exception) {
        Log.e("Contacts", "Failed to save contacts", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
fun bad_case_9(context: Context) {
    val passwordHints = "Bank: mother's maiden name\nEmail: first pet's name"
    
    try {
        // ruleid: kotlin-unencrypted-files-in-app
        val fos = context.openFileOutput("password_hints.txt", Context.MODE_PRIVATE)
        fos.write(passwordHints.toByteArray())
        fos.close()
    } catch (e: Exception) {
        Log.e("PasswordManager", "Failed to save password hints", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
fun bad_case_10(context: Context) {
    val backupData = "Backup of all user preferences and settings"
    
    try {
        // ruleid: kotlin-unencrypted-files-in-app
        val file = File(context.filesDir, "backup.dat")
        file.writeText(backupData)
    } catch (e: Exception) {
        Log.e("Backup", "Failed to create backup", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
fun bad_case_11(context: Context) {
    val userMessages = "To: Jane\nMessage: Let's meet at the cafe tomorrow"
    
    try {
        // ruleid: kotlin-unencrypted-files-in-app
        val outputStream = context.openFileOutput("messages.txt", Context.MODE_APPEND)
        outputStream.write(userMessages.toByteArray())
        outputStream.close()
    } catch (e: Exception) {
        Log.e("Messages", "Failed to save messages", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
fun bad_case_12() {
    val financialData = "Account: 123456789\nBalance: $10,000"
    
    try {
        // ruleid: kotlin-unencrypted-files-in-app
        val file = File("/data/data/com.example.app/files/financial.txt")
        val writer = PrintWriter(file)
        writer.println(financialData)
        writer.close()
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
fun bad_case_13(context: Context) {
    val medicalAppointments = "Dr. Smith: 10/15/2023 2:30 PM - Annual Physical"
    
    try {
        // ruleid: kotlin-unencrypted-files-in-app
        val fos = FileOutputStream(File(context.filesDir, "appointments.txt"))
        val osw = OutputStreamWriter(fos)
        osw.write(medicalAppointments)
        osw.close()
    } catch (e: Exception) {
        Log.e("MedicalApp", "Failed to save appointments", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
fun bad_case_14(context: Context) {
    val authToken = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    
    try {
        // ruleid: kotlin-unencrypted-files-in-app
        val file = File(context.cacheDir, "auth_token.txt")
        val fos = FileOutputStream(file)
        fos.write(authToken.toByteArray())
        fos.close()
    } catch (e: Exception) {
        Log.e("Auth", "Failed to cache auth token", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
fun bad_case_15(context: Context) {
    val userPreferences = "theme=dark\nnotifications=enabled\nlanguage=en"
    
    try {
        // ruleid: kotlin-unencrypted-files-in-app
        val file = File(context.filesDir, "user_prefs.cfg")
        val writer = BufferedWriter(OutputStreamWriter(FileOutputStream(file)))
        writer.write(userPreferences)
        writer.close()
    } catch (e: Exception) {
        Log.e("Preferences", "Failed to save user preferences", e)
    }
}
// {/fact}

// TRUE NEGATIVES - Secure code examples

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
fun good_case_1(context: Context) {
    try {
        val fileName = "user_credentials.txt"
        val fileContents = "username=admin\npassword=secret123"
        
        // Generate a secure key
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256)
        val secretKey = keyGenerator.generateKey()
        
        // Encrypt the data
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val ivParameterSpec = IvParameterSpec(ByteArray(16))
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec)
        val encryptedData = cipher.doFinal(fileContents.toByteArray())
        
        // ok: kotlin-unencrypted-files-in-app
        val fileOutputStream = context.openFileOutput(fileName, Context.MODE_PRIVATE)
        fileOutputStream.write(encryptedData)
        fileOutputStream.close()
        
        Log.d("FileStorage", "Saved encrypted user credentials to file")
    } catch (e: Exception) {
        Log.e("FileStorage", "Error saving credentials", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
fun good_case_2(context: Context) {
    val sensitiveData = "Credit Card: 4111-1111-1111-1111, Exp: 12/25, CVV: 123"
    
    try {
        // Generate encryption key
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            "my_key",
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .build()
        
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
        
        // Get the key
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val secretKeyEntry = keyStore.getEntry("my_key", null) as KeyStore.SecretKeyEntry
        val secretKey = secretKeyEntry.secretKey
        
        // Encrypt data
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val encryptedData = cipher.doFinal(sensitiveData.toByteArray())
        
        // ok: kotlin-unencrypted-files-in-app
        val file = File(context.filesDir, "payment_info.enc")
        val outputStream = FileOutputStream(file)
        outputStream.write(iv)
        outputStream.write(encryptedData)
        outputStream.close()
        
        Log.d("PaymentInfo", "Saved encrypted payment information")
    } catch (e: Exception) {
        Log.e("PaymentInfo", "Failed to save payment info", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
fun good_case_3(context: Context) {
    val userHealthData = "Patient: John Doe, Blood Type: O+, Conditions: Hypertension"
    
    try {
        // Generate a random key
        val key = ByteArray(32)
        SecureRandom().nextBytes(key)
        val secretKey = SecretKeySpec(key, "AES")
        
        // Encrypt the data
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val encryptedData = cipher.doFinal(userHealthData.toByteArray())
        
        // ok: kotlin-unencrypted-files-in-app
        val fos = FileOutputStream(File(context.filesDir, "health_records.enc"))
        fos.write(iv)
        fos.write(encryptedData)
        fos.close()
        
        // Store the key securely (simplified for example)
        val keyFile = File(context.filesDir, "health_key.bin")
        val keyFos = FileOutputStream(keyFile)
        keyFos.write(key)
        keyFos.close()
        
        Log.d("HealthApp", "Saved encrypted health data")
    } catch (e: Exception) {
        Log.e("HealthApp", "Failed to save health data", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
fun good_case_4(context: Context) {
    // Using Android's EncryptedFile API (added in API level 29)
    // This is a simplified example - in real code, you'd need to handle API level compatibility
    
    val apiKeys = "API_KEY=abc123def456\nSECRET_KEY=xyz789uvw"
    
    try {
        // Generate or retrieve master key
        val masterKeyAlias = "master_key"
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            masterKeyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .build()
        
        // For demonstration purposes only - in real code, check if key exists first
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
        
        // ok: kotlin-unencrypted-files-in-app
        // In a real app, you would use EncryptedFile from androidx.security:security-crypto library
        // This is a simplified example showing the concept
        val file = File(context.filesDir, "api_keys.enc")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val secretKey = keyStore.getKey(masterKeyAlias, null) as SecretKey
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val encryptedData = cipher.doFinal(apiKeys.toByteArray())
        
        val outputStream = FileOutputStream(file)
        outputStream.write(iv.size)
        outputStream.write(iv)
        outputStream.write(encryptedData)
        outputStream.close()
        
        Log.d("APIConfig", "API keys saved to encrypted storage")
    } catch (e: Exception) {
        Log.e("APIConfig", "Failed to save API keys", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
fun good_case_5() {
    val personalNotes = "Remember to call therapist about anxiety issues"
    
    try {
        // Create encryption key
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256)
        val key = keyGenerator.generateKey()
        
        // Encrypt data
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val ivBytes = ByteArray(16)
        SecureRandom().nextBytes(ivBytes)
        val ivSpec = IvParameterSpec(ivBytes)
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
        val encryptedData = cipher.doFinal(personalNotes.toByteArray())
        
        // ok: kotlin-unencrypted-files-in-app
        val file = File("/data/data/com.example.app/files/notes.enc")
        val outputStream = FileOutputStream(file)
        outputStream.write(ivBytes)
        outputStream.write(encryptedData)
        outputStream.close()
        
        // Save key securely (simplified)
        val keyFile = File("/data/data/com.example.app/files/notes.key")
        val keyOutputStream = FileOutputStream(keyFile)
        keyOutputStream.write(key.encoded)
        keyOutputStream.close()
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
fun good_case_6(context: Context) {
    val loginSession = "session_token=a1b2c3d4e5f6g7h8i9j0"
    
    try {
        // Generate encryption key
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            "session_key",
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .build()
        
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
        
        // Get the key and encrypt
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val key = keyStore.getKey("session_key", null) as SecretKey
        
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val encryptedData = cipher.doFinal(loginSession.toByteArray())
        
        // ok: kotlin-unencrypted-files-in-app
        val file = File(context.filesDir, "session.enc")
        val outputStream = FileOutputStream(file)
        outputStream.write(iv.size)
        outputStream.write(iv)
        outputStream.write(encryptedData)
        outputStream.close()
    } catch (e: Exception) {
        Log.e("Session", "Failed to save session data", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
fun good_case_7(context: Context) {
    val locationHistory = "Home: 37.7749° N, 122.4194° W\nWork: 37.3861° N, 122.0839° W"
    
    try {
        // Generate key
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256)
        val secretKey = keyGenerator.generateKey()
        
        // Encrypt data
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val encryptedData = cipher.doFinal(locationHistory.toByteArray())
        
        // ok: kotlin-unencrypted-files-in-app
        val fos = context.openFileOutput("location_history.enc", Context.MODE_PRIVATE)
        fos.write(iv)
        fos.write(encryptedData)
        fos.close()
        
        // Store key securely (simplified)
        val keyFos = context.openFileOutput("location_key.bin", Context.MODE_PRIVATE)
        keyFos.write(secretKey.encoded)
        keyFos.close()
    } catch (e: Exception) {
        Log.e("LocationTracker", "Failed to save location history", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
fun good_case_8(context: Context) {
    val contactsList = "John Doe: 555-1234\nJane Smith: 555-5678"
    
    try {
        // Generate encryption key
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            "contacts_key",
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .build()
        
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
        
        // Get the key
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val key = keyStore.getKey("contacts_key", null) as SecretKey
        
        // Encrypt data
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val encryptedData = cipher.doFinal(contactsList.toByteArray())
        
        // ok: kotlin-unencrypted-files-in-app
        val file = File(context.getExternalFilesDir(null), "contacts.enc")
        val outputStream = FileOutputStream(file)
        outputStream.write(iv)
        outputStream.write(encryptedData)
        outputStream.close()
    } catch (e: Exception) {
        Log.e("Contacts", "Failed to save contacts", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
fun good_case_9(context: Context) {
    val passwordHints = "Bank: mother's maiden name\nEmail: first pet's name"
    
    try {
        // Generate a random key
        val key = ByteArray(32)
        SecureRandom().nextBytes(key)
        val secretKey = SecretKeySpec(key, "AES")
        
        // Encrypt the data
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val encryptedData = cipher.doFinal(passwordHints.toByteArray())
        
        // ok: kotlin-unencrypted-files-in-app
        val fos = context.openFileOutput("password_hints.enc", Context.MODE_PRIVATE)
        fos.write(iv)
        fos.write(encryptedData)
        fos.close()
        
        // Store the key securely (simplified)
        val keyFos = context.openFileOutput("password_hints.key", Context.MODE_PRIVATE)
        keyFos.write(key)
        keyFos.close()
    } catch (e: Exception) {
        Log.e("PasswordManager", "Failed to save password hints", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
fun good_case_10(context: Context) {
    val backupData = "Backup of all user preferences and settings"
    
    try {
        // Generate encryption key
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            "backup_key",
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .build()
        
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
        
        // Get the key
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val key = keyStore.getKey("backup_key", null) as SecretKey
        
        // Encrypt data
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val encryptedData = cipher.doFinal(backupData.toByteArray())
        
        // ok: kotlin-unencrypted-files-in-app
        val file = File(context.filesDir, "backup.enc")
        val outputStream = FileOutputStream(file)
        outputStream.write(iv.size)
        outputStream.write(iv)
        outputStream.write(encryptedData)
        outputStream.close()
    } catch (e: Exception) {
        Log.e("Backup", "Failed to create backup", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
fun good_case_11(context: Context) {
    val userMessages = "To: Jane\nMessage: Let's meet at the cafe tomorrow"
    
    try {
        // Generate a secure key
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256)
        val secretKey = keyGenerator.generateKey()
        
        // Encrypt the data
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val ivParameterSpec = IvParameterSpec(ByteArray(16))
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec)
        val encryptedData = cipher.doFinal(userMessages.toByteArray())
        
        // ok: kotlin-unencrypted-files-in-app
        val outputStream = context.openFileOutput("messages.enc", Context.MODE_APPEND)
        outputStream.write(encryptedData)
        outputStream.close()
        
        // Save the key securely (simplified)
        val keyOutputStream = context.openFileOutput("messages.key", Context.MODE_PRIVATE)
        keyOutputStream.write(secretKey.encoded)
        keyOutputStream.close()
    } catch (e: Exception) {
        Log.e("Messages", "Failed to save messages", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
fun good_case_12() {
    val financialData = "Account: 123456789\nBalance: $10,000"
    
    try {
        // Generate encryption key
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256)
        val key = keyGenerator.generateKey()
        
        // Encrypt data
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val ivBytes = ByteArray(16)
        SecureRandom().nextBytes(ivBytes)
        val ivSpec = IvParameterSpec(ivBytes)
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
        val encryptedData = cipher.doFinal(financialData.toByteArray())
        
        // ok: kotlin-unencrypted-files-in-app
        val file = File("/data/data/com.example.app/files/financial.enc")
        val outputStream = FileOutputStream(file)
        outputStream.write(ivBytes)
        outputStream.write(encryptedData)
        outputStream.close()
        
        // Save key securely (simplified)
        val keyFile = File("/data/data/com.example.app/files/financial.key")
        val keyOutputStream = FileOutputStream(keyFile)
        keyOutputStream.write(key.encoded)
        keyOutputStream.close()
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
fun good_case_13(context: Context) {
    val medicalAppointments = "Dr. Smith: 10/15/2023 2:30 PM - Annual Physical"
    
    try {
        // Generate encryption key
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            "appointments_key",
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .build()
        
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
        
        // Get the key
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val key = keyStore.getKey("appointments_key", null) as SecretKey
        
        // Encrypt data
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val encryptedData = cipher.doFinal(medicalAppointments.toByteArray())
        
        // ok: kotlin-unencrypted-files-in-app
        val file = File(context.filesDir, "appointments.enc")
        val outputStream = FileOutputStream(file)
        outputStream.write(iv)
        outputStream.write(encryptedData)
        outputStream.close()
    } catch (e: Exception) {
        Log.e("MedicalApp", "Failed to save appointments", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
fun good_case_14(context: Context) {
    val authToken = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    
    try {
        // Generate a random key
        val key = ByteArray(32)
        SecureRandom().nextBytes(key)
        val secretKey = SecretKeySpec(key, "AES")
        
        // Encrypt the data
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val encryptedData = cipher.doFinal(authToken.toByteArray())
        
        // ok: kotlin-unencrypted-files-in-app
        val file = File(context.cacheDir, "auth_token.enc")
        val outputStream = FileOutputStream(file)
        outputStream.write(iv)
        outputStream.write(encryptedData)
        outputStream.close()
        
        // Store the key securely (simplified)
        val keyFile = File(context.filesDir, "auth_token.key")
        val keyOutputStream = FileOutputStream(keyFile)
        keyOutputStream.write(key)
        keyOutputStream.close()
    } catch (e: Exception) {
        Log.e("Auth", "Failed to cache auth token", e)
    }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
fun good_case_15(context: Context) {
    val userPreferences = "theme=dark\nnotifications=enabled\nlanguage=en"
    
    try {
        // Generate encryption key
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            "prefs_key",
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .build()
        
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
        
        // Get the key
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val key = keyStore.getKey("prefs_key", null) as SecretKey
        
        // Encrypt data
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val encryptedData = cipher.doFinal(userPreferences.toByteArray())
        
        // ok: kotlin-unencrypted-files-in-app
        val file = File(context.filesDir, "user_prefs.enc")
        val outputStream = FileOutputStream(file)
        outputStream.write(iv)
        outputStream.write(encryptedData)
        outputStream.close()
    } catch (e: Exception) {
        Log.e("Preferences", "Failed to save user preferences", e)
    }
}
// {/fact}