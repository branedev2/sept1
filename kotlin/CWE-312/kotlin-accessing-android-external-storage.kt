import android.content.Context
import android.os.Environment
import java.io.File
import java.io.FileOutputStream
import java.io.FileInputStream
import java.io.OutputStreamWriter
import java.io.InputStreamReader
import android.util.Log
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import java.security.KeyStore
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.BufferedReader
import java.io.BufferedWriter
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-connection@v1.0 defects=1}
fun bad_case_1(context: Context) {
    val userPassword = "supersecretpassword123"
    val file = File(Environment.getExternalStorageDirectory(), "credentials.txt")
    
    try {
        // ruleid: kotlin-accessing-android-external-storage
        val outputStream = FileOutputStream(file)
        val writer = OutputStreamWriter(outputStream)
        writer.write("Password: $userPassword")
        writer.close()
        outputStream.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write to external storage", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
fun bad_case_2(context: Context) {
    val apiKey = "api_key_12345abcde"
    val directory = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS)
    val file = File(directory, "api_config.txt")
    
    try {
        // ruleid: kotlin-accessing-android-external-storage
        val outputStream = FileOutputStream(file)
        outputStream.write(apiKey.toByteArray())
        outputStream.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write to external storage", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
fun bad_case_3(context: Context) {
    val userCredentials = mapOf("username" to "admin", "password" to "admin123")
    val externalDir = context.getExternalFilesDir(null)
    val file = File(externalDir, "user_data.txt")
    
    try {
        // ruleid: kotlin-accessing-android-external-storage
        val writer = file.bufferedWriter()
        writer.write("Username: ${userCredentials["username"]}\n")
        writer.write("Password: ${userCredentials["password"]}")
        writer.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write to external storage", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
fun bad_case_4(context: Context) {
    val sessionToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    val externalCacheDir = context.externalCacheDir
    val tokenFile = File(externalCacheDir, "session.token")
    
    try {
        // ruleid: kotlin-accessing-android-external-storage
        val outputStream = FileOutputStream(tokenFile)
        outputStream.write(sessionToken.toByteArray())
        outputStream.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write to external cache", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
fun bad_case_5(context: Context) {
    val creditCardInfo = "Card: 4111-1111-1111-1111, Exp: 12/25, CVV: 123"
    val externalDir = Environment.getExternalStorageDirectory()
    val paymentDir = File(externalDir, "payment_info")
    paymentDir.mkdirs()
    val paymentFile = File(paymentDir, "card_details.txt")
    
    try {
        // ruleid: kotlin-accessing-android-external-storage
        val writer = BufferedWriter(OutputStreamWriter(FileOutputStream(paymentFile)))
        writer.write(creditCardInfo)
        writer.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write payment info", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
fun bad_case_6(context: Context) {
    val databaseCredentials = "jdbc:mysql://localhost:3306/mydb?user=root&password=rootpassword"
    val state = Environment.getExternalStorageState()
    
    if (Environment.MEDIA_MOUNTED == state) {
        val file = File(Environment.getExternalStorageDirectory(), "database_config.properties")
        try {
            // ruleid: kotlin-accessing-android-external-storage
            val outputStream = FileOutputStream(file)
            outputStream.write(databaseCredentials.toByteArray())
            outputStream.close()
        } catch (e: Exception) {
            Log.e("SecurityError", "Failed to write database config", e)
        }
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
fun bad_case_7(context: Context) {
    val userProfile = """
        {
            "name": "John Doe",
            "email": "john@example.com",
            "ssn": "123-45-6789"
        }
    """.trimIndent()
    
    val externalDir = context.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS)
    val profileFile = File(externalDir, "profile.json")
    
    try {
        // ruleid: kotlin-accessing-android-external-storage
        val outputStream = FileOutputStream(profileFile)
        outputStream.write(userProfile.toByteArray())
        outputStream.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write profile data", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
fun bad_case_8(context: Context) {
    val backupData = "This is sensitive backup data that should be protected"
    val externalStorageDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
    val backupFile = File(externalStorageDir, "app_backup.dat")
    
    try {
        // ruleid: kotlin-accessing-android-external-storage
        val outputStream = FileOutputStream(backupFile)
        outputStream.write(backupData.toByteArray())
        outputStream.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write backup data", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
fun bad_case_9(context: Context) {
    val privateKey = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEF..."
    val externalDir = Environment.getExternalStorageDirectory()
    val keyFile = File(externalDir, ".keys/private.pem")
    keyFile.parentFile?.mkdirs()
    
    try {
        // ruleid: kotlin-accessing-android-external-storage
        val outputStream = FileOutputStream(keyFile)
        outputStream.write(privateKey.toByteArray())
        outputStream.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write private key", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
fun bad_case_10(context: Context) {
    val authToken = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    val externalDir = context.getExternalFilesDir(null)
    val configFile = File(externalDir, "auth_config.txt")
    
    try {
        // ruleid: kotlin-accessing-android-external-storage
        val writer = configFile.writer()
        writer.write("AUTH_TOKEN=$authToken")
        writer.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write auth token", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
fun bad_case_11(context: Context) {
    val loginData = "username=admin&password=secretpass123"
    val externalDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS)
    val loginFile = File(externalDir, "login_data.txt")
    
    try {
        // ruleid: kotlin-accessing-android-external-storage
        val outputStream = FileOutputStream(loginFile)
        outputStream.write(loginData.toByteArray())
        outputStream.flush()
        outputStream.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write login data", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
fun bad_case_12(context: Context) {
    val encryptionKey = "1234567890abcdef"
    val externalDir = context.getExternalFilesDir(Environment.DIRECTORY_PICTURES)
    val keyFile = File(externalDir, ".secret_key")
    
    try {
        // ruleid: kotlin-accessing-android-external-storage
        val outputStream = FileOutputStream(keyFile)
        val writer = OutputStreamWriter(outputStream)
        writer.write(encryptionKey)
        writer.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write encryption key", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
fun bad_case_13(context: Context) {
    val sensitiveData = "This data should not be stored externally"
    val externalDir = Environment.getExternalStorageDirectory()
    val dataFile = File(externalDir, "app_data/sensitive.dat")
    dataFile.parentFile?.mkdirs()
    
    try {
        // ruleid: kotlin-accessing-android-external-storage
        val outputStream = FileOutputStream(dataFile)
        outputStream.write(sensitiveData.toByteArray())
        outputStream.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write sensitive data", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
fun bad_case_14(context: Context) {
    val healthData = "Patient: John Doe, Condition: Diabetes, Medication: Insulin"
    val externalDir = context.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS)
    val healthFile = File(externalDir, "health_records.txt")
    
    try {
        // ruleid: kotlin-accessing-android-external-storage
        val writer = BufferedWriter(OutputStreamWriter(FileOutputStream(healthFile)))
        writer.write(healthData)
        writer.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write health data", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
fun bad_case_15(context: Context) {
    val accountInfo = "Account: 123456789, Routing: 987654321"
    val externalDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
    val accountFile = File(externalDir, "banking_info.txt")
    
    try {
        // ruleid: kotlin-accessing-android-external-storage
        val outputStream = FileOutputStream(accountFile)
        outputStream.write(accountInfo.toByteArray())
        outputStream.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write account info", e)
    }
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-connection@v1.0 defects=0}
fun good_case_1(context: Context) {
    val userPassword = "supersecretpassword123"
    
    try {
        // ok: kotlin-accessing-android-external-storage
        val outputStream = context.openFileOutput("credentials.txt", Context.MODE_PRIVATE)
        val writer = OutputStreamWriter(outputStream)
        writer.write("Password: $userPassword")
        writer.close()
        outputStream.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write to internal storage", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
fun good_case_2(context: Context) {
    val apiKey = "api_key_12345abcde"
    
    try {
        // ok: kotlin-accessing-android-external-storage
        val file = File(context.filesDir, "api_config.txt")
        val outputStream = FileOutputStream(file)
        outputStream.write(apiKey.toByteArray())
        outputStream.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write to internal storage", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
fun good_case_3(context: Context) {
    val userCredentials = mapOf("username" to "admin", "password" to "admin123")
    
    try {
        // ok: kotlin-accessing-android-external-storage
        val file = File(context.filesDir, "user_data.txt")
        val writer = file.bufferedWriter()
        writer.write("Username: ${userCredentials["username"]}\n")
        writer.write("Password: ${userCredentials["password"]}")
        writer.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write to internal storage", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
fun good_case_4(context: Context) {
    val sessionToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    
    try {
        // ok: kotlin-accessing-android-external-storage
        val tokenFile = File(context.cacheDir, "session.token")
        val outputStream = FileOutputStream(tokenFile)
        outputStream.write(sessionToken.toByteArray())
        outputStream.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write to internal cache", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
fun good_case_5(context: Context) {
    val creditCardInfo = "Card: 4111-1111-1111-1111, Exp: 12/25, CVV: 123"
    
    try {
        // ok: kotlin-accessing-android-external-storage
        val paymentDir = File(context.filesDir, "payment_info")
        paymentDir.mkdirs()
        val paymentFile = File(paymentDir, "card_details.txt")
        val writer = BufferedWriter(OutputStreamWriter(FileOutputStream(paymentFile)))
        writer.write(creditCardInfo)
        writer.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write payment info", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
fun good_case_6(context: Context) {
    val databaseCredentials = "jdbc:mysql://localhost:3306/mydb?user=root&password=rootpassword"
    
    try {
        // ok: kotlin-accessing-android-external-storage
        val sharedPreferences = context.getSharedPreferences("DatabaseConfig", Context.MODE_PRIVATE)
        val editor = sharedPreferences.edit()
        editor.putString("connection_string", databaseCredentials)
        editor.apply()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to save database config", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
fun good_case_7(context: Context) {
    val userProfile = """
        {
            "name": "John Doe",
            "email": "john@example.com",
            "ssn": "123-45-6789"
        }
    """.trimIndent()
    
    try {
        // ok: kotlin-accessing-android-external-storage
        val profileFile = File(context.filesDir, "profile.json")
        val outputStream = FileOutputStream(profileFile)
        outputStream.write(userProfile.toByteArray())
        outputStream.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write profile data", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
fun good_case_8(context: Context) {
    val backupData = "This is sensitive backup data that should be protected"
    
    try {
        // Create an encrypted file using AndroidX Security
        // ok: kotlin-accessing-android-external-storage
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        
        val encryptedFile = EncryptedFile.Builder(
            context,
            File(context.filesDir, "app_backup.dat"),
            masterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build()
        
        val outputStream = encryptedFile.openFileOutput()
        outputStream.write(backupData.toByteArray())
        outputStream.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write encrypted backup data", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
fun good_case_9(context: Context) {
    val privateKey = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEF..."
    
    try {
        // ok: kotlin-accessing-android-external-storage
        val keyFile = File(context.filesDir, ".keys/private.pem")
        keyFile.parentFile?.mkdirs()
        val outputStream = FileOutputStream(keyFile)
        outputStream.write(privateKey.toByteArray())
        outputStream.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write private key", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
fun good_case_10(context: Context) {
    val authToken = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    
    try {
        // ok: kotlin-accessing-android-external-storage
        val sharedPreferences = context.getSharedPreferences("AuthPrefs", Context.MODE_PRIVATE)
        val editor = sharedPreferences.edit()
        editor.putString("auth_token", authToken)
        editor.apply()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to save auth token", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
fun good_case_11(context: Context) {
    val loginData = "username=admin&password=secretpass123"
    
    try {
        // ok: kotlin-accessing-android-external-storage
        val loginFile = File(context.filesDir, "login_data.txt")
        val outputStream = FileOutputStream(loginFile)
        outputStream.write(loginData.toByteArray())
        outputStream.flush()
        outputStream.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write login data", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
fun good_case_12(context: Context) {
    val encryptionKey = "1234567890abcdef"
    
    try {
        // Using Android Keystore for secure key storage
        // ok: kotlin-accessing-android-external-storage
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        
        val keyGenerator = javax.crypto.KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
        )
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            "encryption_key_alias",
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .build()
        
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to store encryption key in KeyStore", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
fun good_case_13(context: Context) {
    val sensitiveData = "This data should not be stored externally"
    
    try {
        // ok: kotlin-accessing-android-external-storage
        val dataFile = File(context.filesDir, "app_data/sensitive.dat")
        dataFile.parentFile?.mkdirs()
        val outputStream = FileOutputStream(dataFile)
        outputStream.write(sensitiveData.toByteArray())
        outputStream.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write sensitive data", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
fun good_case_14(context: Context) {
    val healthData = "Patient: John Doe, Condition: Diabetes, Medication: Insulin"
    
    try {
        // Create an encrypted file using AndroidX Security
        // ok: kotlin-accessing-android-external-storage
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        
        val encryptedFile = EncryptedFile.Builder(
            context,
            File(context.filesDir, "health_records.txt"),
            masterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build()
        
        val outputStream = encryptedFile.openFileOutput()
        outputStream.write(healthData.toByteArray())
        outputStream.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write encrypted health data", e)
    }
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
fun good_case_15(context: Context) {
    val accountInfo = "Account: 123456789, Routing: 987654321"
    
    try {
        // ok: kotlin-accessing-android-external-storage
        val accountFile = File(context.filesDir, "banking_info.txt")
        val outputStream = FileOutputStream(accountFile)
        
        // Encrypt the data before storing
        val secretKey = SecretKeySpec("MySecretKey12345".toByteArray(), "AES")
        val cipher = Cipher.getInstance("AES")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val encryptedData = cipher.doFinal(accountInfo.toByteArray())
        
        outputStream.write(encryptedData)
        outputStream.close()
    } catch (e: Exception) {
        Log.e("SecurityError", "Failed to write encrypted account info", e)
    }
}
// {/fact}