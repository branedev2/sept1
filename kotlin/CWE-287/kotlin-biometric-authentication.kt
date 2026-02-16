import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.widget.Button
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.security.KeyStore
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import java.security.Signature
import java.security.KeyPairGenerator
import java.security.KeyPair

// True Positive Examples (Vulnerable Code)

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_1(activity: AppCompatActivity) {
    val executor = ContextCompat.getMainExecutor(activity)
    val biometricPrompt = BiometricPrompt(activity, executor, 
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                // Access sensitive data without cryptographic protection
                accessSensitiveData()
            }
        })
    
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Biometric Authentication")
        .setSubtitle("Log in using your biometric credential")
        .setNegativeButtonText("Cancel")
        .build()
    
    // ruleid: kotlin-biometric-authentication
    biometricPrompt.authenticate(promptInfo)
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_2(activity: AppCompatActivity) {
    val executor = ContextCompat.getMainExecutor(activity)
    val callback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            super.onAuthenticationSucceeded(result)
            // Proceed with sensitive operation
            decryptSensitiveData()
        }
    }
    
    val biometricPrompt = BiometricPrompt(activity, executor, callback)
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Authentication Required")
        .setSubtitle("Please verify your identity")
        .setNegativeButtonText("Cancel")
        .build()
    
    // ruleid: kotlin-biometric-authentication
    biometricPrompt.authenticate(promptInfo)
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_3(activity: AppCompatActivity) {
    val biometricManager = BiometricManager.from(activity)
    if (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == 
        BiometricManager.BIOMETRIC_SUCCESS) {
        
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(activity, executor, 
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    // Perform sensitive operation
                    performSensitiveTransaction()
                }
            })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric Authentication")
            .setSubtitle("Authenticate to proceed")
            .setNegativeButtonText("Cancel")
            .build()
        
        // ruleid: kotlin-biometric-authentication
        biometricPrompt.authenticate(promptInfo)
    }
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_4(activity: AppCompatActivity) {
    val executor = ContextCompat.getMainExecutor(activity)
    
    // Create biometric prompt
    val biometricPrompt = BiometricPrompt(activity, executor, 
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                Toast.makeText(activity, "Authentication succeeded!", Toast.LENGTH_SHORT).show()
                // Access protected content
                showProtectedContent()
            }
        })
    
    // Configure prompt info
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Verify Identity")
        .setSubtitle("Use your fingerprint to access secure data")
        .setNegativeButtonText("Use Password")
        .build()
    
    // Authenticate without CryptoObject
    // ruleid: kotlin-biometric-authentication
    biometricPrompt.authenticate(promptInfo)
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_5(activity: AppCompatActivity) {
    val button = activity.findViewById<Button>(R.id.authenticate_button)
    button.setOnClickListener {
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(activity, executor, 
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    // Process payment
                    processPayment()
                }
            })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Payment Confirmation")
            .setSubtitle("Confirm payment using biometric")
            .setNegativeButtonText("Cancel")
            .build()
        
        // ruleid: kotlin-biometric-authentication
        biometricPrompt.authenticate(promptInfo)
    }
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_6(activity: AppCompatActivity) {
    class BiometricHelper(private val activity: AppCompatActivity) {
        private val executor = ContextCompat.getMainExecutor(activity)
        
        fun authenticateUser() {
            val biometricPrompt = BiometricPrompt(activity, executor, 
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        // Grant access to secure area
                        grantAccess()
                    }
                })
            
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authentication")
                .setSubtitle("Authenticate to continue")
                .setNegativeButtonText("Cancel")
                .build()
            
            // ruleid: kotlin-biometric-authentication
            biometricPrompt.authenticate(promptInfo)
        }
        
        private fun grantAccess() {
            // Grant access to secure area
        }
    }
    
    val helper = BiometricHelper(activity)
    helper.authenticateUser()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_7(activity: AppCompatActivity) {
    val executor = ContextCompat.getMainExecutor(activity)
    
    // Check if device supports biometric authentication
    val biometricManager = BiometricManager.from(activity)
    when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
        BiometricManager.BIOMETRIC_SUCCESS -> {
            val biometricPrompt = BiometricPrompt(activity, executor, 
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        // Access secure notes
                        accessSecureNotes()
                    }
                })
            
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Access Secure Notes")
                .setSubtitle("Use biometric to unlock")
                .setNegativeButtonText("Cancel")
                .build()
            
            // ruleid: kotlin-biometric-authentication
            biometricPrompt.authenticate(promptInfo)
        }
        else -> {
            Toast.makeText(activity, "Biometric authentication not available", Toast.LENGTH_SHORT).show()
        }
    }
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_8(activity: AppCompatActivity) {
    val authButton = activity.findViewById<Button>(R.id.auth_button)
    authButton.setOnClickListener {
        val executor = ContextCompat.getMainExecutor(activity)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                // Access encrypted files
                accessEncryptedFiles()
            }
        }
        
        val biometricPrompt = BiometricPrompt(activity, executor, callback)
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Access Files")
            .setSubtitle("Authenticate to access encrypted files")
            .setNegativeButtonText("Cancel")
            .build()
        
        // ruleid: kotlin-biometric-authentication
        biometricPrompt.authenticate(promptInfo)
    }
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_9(activity: AppCompatActivity) {
    fun showBiometricPrompt() {
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(activity, executor, 
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    // Unlock app
                    unlockApp()
                }
            })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("App Lock")
            .setSubtitle("Unlock the app using biometric")
            .setNegativeButtonText("Cancel")
            .build()
        
        // ruleid: kotlin-biometric-authentication
        biometricPrompt.authenticate(promptInfo)
    }
    
    showBiometricPrompt()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_10(activity: AppCompatActivity) {
    val loginButton = activity.findViewById<Button>(R.id.login_button)
    loginButton.setOnClickListener {
        authenticateWithBiometric(activity)
    }
}
// {/fact}

private fun authenticateWithBiometric(activity: AppCompatActivity) {
    val executor = ContextCompat.getMainExecutor(activity)
    val biometricPrompt = BiometricPrompt(activity, executor, 
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                // Login user
                loginUser()
            }
        })
    
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Login")
        .setSubtitle("Log in with your biometric credential")
        .setNegativeButtonText("Use Password")
        .build()
    
    // ruleid: kotlin-biometric-authentication
    biometricPrompt.authenticate(promptInfo)
}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_11(activity: AppCompatActivity) {
    val biometricManager = BiometricManager.from(activity)
    if (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG or 
                                         BiometricManager.Authenticators.DEVICE_CREDENTIAL) == 
        BiometricManager.BIOMETRIC_SUCCESS) {
        
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(activity, executor, 
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    // Access health data
                    accessHealthData()
                }
            })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Health Data Access")
            .setSubtitle("Authenticate to view health records")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or 
                                     BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            .build()
        
        // ruleid: kotlin-biometric-authentication
        biometricPrompt.authenticate(promptInfo)
    }
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_12(activity: AppCompatActivity) {
    val executor = ContextCompat.getMainExecutor(activity)
    
    // Create authentication callback
    val authCallback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            super.onAuthenticationSucceeded(result)
            // Access financial data
            accessFinancialData()
        }
    }
    
    // Create biometric prompt
    val biometricPrompt = BiometricPrompt(activity, executor, authCallback)
    
    // Configure prompt info
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Financial Data")
        .setSubtitle("Authenticate to view your financial data")
        .setNegativeButtonText("Cancel")
        .build()
    
    // ruleid: kotlin-biometric-authentication
    biometricPrompt.authenticate(promptInfo)
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_13(activity: AppCompatActivity) {
    val settingsButton = activity.findViewById<Button>(R.id.settings_button)
    settingsButton.setOnClickListener {
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(activity, executor, 
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    // Access app settings
                    openSecureSettings()
                }
            })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Secure Settings")
            .setSubtitle("Authenticate to access secure settings")
            .setNegativeButtonText("Cancel")
            .build()
        
        // ruleid: kotlin-biometric-authentication
        biometricPrompt.authenticate(promptInfo)
    }
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_14(activity: AppCompatActivity) {
    fun authenticateForPasswordManager() {
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(activity, executor, 
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    // Show stored passwords
                    showStoredPasswords()
                }
            })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Password Manager")
            .setSubtitle("Authenticate to view your passwords")
            .setNegativeButtonText("Cancel")
            .build()
        
        // ruleid: kotlin-biometric-authentication
        biometricPrompt.authenticate(promptInfo)
    }
    
    authenticateForPasswordManager()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_15(activity: AppCompatActivity) {
    val biometricManager = BiometricManager.from(activity)
    
    if (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK) == 
        BiometricManager.BIOMETRIC_SUCCESS) {
        
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(activity, executor, 
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    // Access document vault
                    openDocumentVault()
                }
            })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Document Vault")
            .setSubtitle("Authenticate to access your documents")
            .setNegativeButtonText("Cancel")
            .build()
        
        // ruleid: kotlin-biometric-authentication
        biometricPrompt.authenticate(promptInfo)
    }
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_1(activity: AppCompatActivity) {
    val executor = ContextCompat.getMainExecutor(activity)
    val biometricPrompt = BiometricPrompt(activity, executor, 
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                val cryptoObject = result.cryptoObject
                if (cryptoObject != null && cryptoObject.cipher != null) {
                    // Use the cipher to decrypt sensitive data
                    decryptWithCipher(cryptoObject.cipher!!)
                }
            }
        })
    
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Biometric Authentication")
        .setSubtitle("Log in using your biometric credential")
        .setNegativeButtonText("Cancel")
        .build()
    
    // Generate cipher for encryption/decryption
    val cipher = getCipher()
    val cryptoObject = BiometricPrompt.CryptoObject(cipher)
    
    // ok: kotlin-biometric-authentication
    biometricPrompt.authenticate(promptInfo, cryptoObject)
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_2(activity: AppCompatActivity) {
    val executor = ContextCompat.getMainExecutor(activity)
    val callback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            super.onAuthenticationSucceeded(result)
            val cryptoObject = result.cryptoObject
            if (cryptoObject != null && cryptoObject.signature != null) {
                // Use the signature for signing data
                signDataWithSignature(cryptoObject.signature!!)
            }
        }
    }
    
    val biometricPrompt = BiometricPrompt(activity, executor, callback)
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Authentication Required")
        .setSubtitle("Please verify your identity")
        .setNegativeButtonText("Cancel")
        .build()
    
    // Generate signature for signing data
    val signature = getSignature()
    val cryptoObject = BiometricPrompt.CryptoObject(signature)
    
    // ok: kotlin-biometric-authentication
    biometricPrompt.authenticate(promptInfo, cryptoObject)
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_3(activity: AppCompatActivity) {
    val biometricManager = BiometricManager.from(activity)
    if (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == 
        BiometricManager.BIOMETRIC_SUCCESS) {
        
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(activity, executor, 
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    val cryptoObject = result.cryptoObject
                    if (cryptoObject != null && cryptoObject.mac != null) {
                        // Use the MAC for verifying data integrity
                        verifyDataWithMac(cryptoObject.mac!!)
                    }
                }
            })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric Authentication")
            .setSubtitle("Authenticate to proceed")
            .setNegativeButtonText("Cancel")
            .build()
        
        // Generate MAC for data integrity verification
        val mac = getMac()
        val cryptoObject = BiometricPrompt.CryptoObject(mac)
        
        // ok: kotlin-biometric-authentication
        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_4(activity: AppCompatActivity) {
    val executor = ContextCompat.getMainExecutor(activity)
    
    // Create biometric prompt
    val biometricPrompt = BiometricPrompt(activity, executor, 
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                val cryptoObject = result.cryptoObject
                if (cryptoObject != null && cryptoObject.cipher != null) {
                    // Decrypt protected content with cipher
                    val decryptedData = decryptData(cryptoObject.cipher!!)
                    showProtectedContent(decryptedData)
                }
            }
        })
    
    // Configure prompt info
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Verify Identity")
        .setSubtitle("Use your fingerprint to access secure data")
        .setNegativeButtonText("Use Password")
        .build()
    
    // Initialize cipher
    val cipher = initCipher()
    val cryptoObject = BiometricPrompt.CryptoObject(cipher)
    
    // ok: kotlin-biometric-authentication
    biometricPrompt.authenticate(promptInfo, cryptoObject)
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_5(activity: AppCompatActivity) {
    val button = activity.findViewById<Button>(R.id.authenticate_button)
    button.setOnClickListener {
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(activity, executor, 
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    val cryptoObject = result.cryptoObject
                    if (cryptoObject != null && cryptoObject.cipher != null) {
                        // Process payment with secure encryption
                        processPaymentSecurely(cryptoObject.cipher!!)
                    }
                }
            })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Payment Confirmation")
            .setSubtitle("Confirm payment using biometric")
            .setNegativeButtonText("Cancel")
            .build()
        
        // Setup encryption for payment data
        val cipher = setupPaymentCipher()
        val cryptoObject = BiometricPrompt.CryptoObject(cipher)
        
        // ok: kotlin-biometric-authentication
        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_6(activity: AppCompatActivity) {
    class SecureBiometricHelper(private val activity: AppCompatActivity) {
        private val executor = ContextCompat.getMainExecutor(activity)
        
        fun authenticateUser() {
            val biometricPrompt = BiometricPrompt(activity, executor, 
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        val cryptoObject = result.cryptoObject
                        if (cryptoObject != null && cryptoObject.signature != null) {
                            // Grant access to secure area with signature verification
                            grantAccessWithSignature(cryptoObject.signature!!)
                        }
                    }
                })
            
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authentication")
                .setSubtitle("Authenticate to continue")
                .setNegativeButtonText("Cancel")
                .build()
            
            // Setup signature for verification
            val signature = setupSignature()
            val cryptoObject = BiometricPrompt.CryptoObject(signature)
            
            // ok: kotlin-biometric-authentication
            biometricPrompt.authenticate(promptInfo, cryptoObject)
        }
        
        private fun grantAccessWithSignature(signature: Signature) {
            // Grant access to secure area with signature verification
        }
        
        private fun setupSignature(): Signature {
            // Setup and initialize signature
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                "signature_key",
                KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .build()
            
            keyPairGenerator.initialize(keyGenParameterSpec)
            keyPairGenerator.generateKeyPair()
            
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(keyStore.getKey("signature_key", null) as java.security.PrivateKey)
            return signature
        }
    }
    
    val helper = SecureBiometricHelper(activity)
    helper.authenticateUser()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_7(activity: AppCompatActivity) {
    val executor = ContextCompat.getMainExecutor(activity)
    
    // Check if device supports biometric authentication
    val biometricManager = BiometricManager.from(activity)
    when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
        BiometricManager.BIOMETRIC_SUCCESS -> {
            val biometricPrompt = BiometricPrompt(activity, executor, 
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        val cryptoObject = result.cryptoObject
                        if (cryptoObject != null && cryptoObject.cipher != null) {
                            // Access secure notes with encryption
                            accessSecureNotesWithEncryption(cryptoObject.cipher!!)
                        }
                    }
                })
            
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Access Secure Notes")
                .setSubtitle("Use biometric to unlock")
                .setNegativeButtonText("Cancel")
                .build()
            
            // Initialize cipher for secure notes
            val cipher = initializeNotesCipher()
            val cryptoObject = BiometricPrompt.CryptoObject(cipher)
            
            // ok: kotlin-biometric-authentication
            biometricPrompt.authenticate(promptInfo, cryptoObject)
        }
        else -> {
            Toast.makeText(activity, "Biometric authentication not available", Toast.LENGTH_SHORT).show()
        }
    }
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_8(activity: AppCompatActivity) {
    val authButton = activity.findViewById<Button>(R.id.auth_button)
    authButton.setOnClickListener {
        val executor = ContextCompat.getMainExecutor(activity)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                val cryptoObject = result.cryptoObject
                if (cryptoObject != null && cryptoObject.cipher != null) {
                    // Access encrypted files with decryption
                    accessEncryptedFilesSecurely(cryptoObject.cipher!!)
                }
            }
        }
        
        val biometricPrompt = BiometricPrompt(activity, executor, callback)
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Access Files")
            .setSubtitle("Authenticate to access encrypted files")
            .setNegativeButtonText("Cancel")
            .build()
        
        // Setup cipher for file decryption
        val cipher = setupFileCipher()
        val cryptoObject = BiometricPrompt.CryptoObject(cipher)
        
        // ok: kotlin-biometric-authentication
        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_9(activity: AppCompatActivity) {
    fun showSecureBiometricPrompt() {
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(activity, executor, 
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    val cryptoObject = result.cryptoObject
                    if (cryptoObject != null && cryptoObject.mac != null) {
                        // Unlock app with MAC verification
                        unlockAppSecurely(cryptoObject.mac!!)
                    }
                }
            })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("App Lock")
            .setSubtitle("Unlock the app using biometric")
            .setNegativeButtonText("Cancel")
            .build()
        
        // Setup MAC for app unlocking
        val mac = setupAppMac()
        val cryptoObject = BiometricPrompt.CryptoObject(mac)
        
        // ok: kotlin-biometric-authentication
        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }
    
    showSecureBiometricPrompt()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_10(activity: AppCompatActivity) {
    val loginButton = activity.findViewById<Button>(R.id.login_button)
    loginButton.setOnClickListener {
        authenticateWithBiometricSecurely(activity)
    }
}
// {/fact}

private fun authenticateWithBiometricSecurely(activity: AppCompatActivity) {
    val executor = ContextCompat.getMainExecutor(activity)
    val biometricPrompt = BiometricPrompt(activity, executor, 
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                val cryptoObject = result.cryptoObject
                if (cryptoObject != null && cryptoObject.cipher != null) {
                    // Login user with secure token decryption
                    loginUserSecurely(cryptoObject.cipher!!)
                }
            }
        })
    
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Login")
        .setSubtitle("Log in with your biometric credential")
        .setNegativeButtonText("Use Password")
        .build()
    
    // Setup cipher for login token
    val cipher = setupLoginCipher()
    val cryptoObject = BiometricPrompt.CryptoObject(cipher)
    
    // ok: kotlin-biometric-authentication
    biometricPrompt.authenticate(promptInfo, cryptoObject)
}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_11(activity: AppCompatActivity) {
    val biometricManager = BiometricManager.from(activity)
    if (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG or 
                                         BiometricManager.Authenticators.DEVICE_CREDENTIAL) == 
        BiometricManager.BIOMETRIC_SUCCESS) {
        
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(activity, executor, 
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    val cryptoObject = result.cryptoObject
                    if (cryptoObject != null && cryptoObject.cipher != null) {
                        // Access health data with secure decryption
                        accessHealthDataSecurely(cryptoObject.cipher!!)
                    }
                }
            })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Health Data Access")
            .setSubtitle("Authenticate to view health records")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or 
                                     BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            .build()
        
        // Setup cipher for health data
        val cipher = setupHealthDataCipher()
        val cryptoObject = BiometricPrompt.CryptoObject(cipher)
        
        // ok: kotlin-biometric-authentication
        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_12(activity: AppCompatActivity) {
    val executor = ContextCompat.getMainExecutor(activity)
    
    // Create authentication callback
    val authCallback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            super.onAuthenticationSucceeded(result)
            val cryptoObject = result.cryptoObject
            if (cryptoObject != null && cryptoObject.signature != null) {
                // Access financial data with signature verification
                accessFinancialDataSecurely(cryptoObject.signature!!)
            }
        }
    }
    
    // Create biometric prompt
    val biometricPrompt = BiometricPrompt(activity, executor, authCallback)
    
    // Configure prompt info
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Financial Data")
        .setSubtitle("Authenticate to view your financial data")
        .setNegativeButtonText("Cancel")
        .build()
    
    // Setup signature for financial data
    val signature = setupFinancialDataSignature()
    val cryptoObject = BiometricPrompt.CryptoObject(signature)
    
    // ok: kotlin-biometric-authentication
    biometricPrompt.authenticate(promptInfo, cryptoObject)
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_13(activity: AppCompatActivity) {
    val settingsButton = activity.findViewById<Button>(R.id.settings_button)
    settingsButton.setOnClickListener {
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(activity, executor, 
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    val cryptoObject = result.cryptoObject
                    if (cryptoObject != null && cryptoObject.mac != null) {
                        // Access app settings with MAC verification
                        openSecureSettingsWithMac(cryptoObject.mac!!)
                    }
                }
            })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Secure Settings")
            .setSubtitle("Authenticate to access secure settings")
            .setNegativeButtonText("Cancel")
            .build()
        
        // Setup MAC for settings access
        val mac = setupSettingsMac()
        val cryptoObject = BiometricPrompt.CryptoObject(mac)
        
        // ok: kotlin-biometric-authentication
        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_14(activity: AppCompatActivity) {
    fun authenticateForPasswordManagerSecurely() {
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(activity, executor, 
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    val cryptoObject = result.cryptoObject
                    if (cryptoObject != null && cryptoObject.cipher != null) {
                        // Show stored passwords with decryption
                        showStoredPasswordsSecurely(cryptoObject.cipher!!)
                    }
                }
            })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Password Manager")
            .setSubtitle("Authenticate to view your passwords")
            .setNegativeButtonText("Cancel")
            .build()
        
        // Setup cipher for password decryption
        val cipher = setupPasswordCipher()
        val cryptoObject = BiometricPrompt.CryptoObject(cipher)
        
        // ok: kotlin-biometric-authentication
        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }
    
    authenticateForPasswordManagerSecurely()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_15(activity: AppCompatActivity) {
    val biometricManager = BiometricManager.from(activity)
    
    if (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK) == 
        BiometricManager.BIOMETRIC_SUCCESS) {
        
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(activity, executor, 
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    val cryptoObject = result.cryptoObject
                    if (cryptoObject != null && cryptoObject.cipher != null) {
                        // Access document vault with decryption
                        openDocumentVaultSecurely(cryptoObject.cipher!!)
                    }
                }
            })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Document Vault")
            .setSubtitle("Authenticate to access your documents")
            .setNegativeButtonText("Cancel")
            .build()
        
        // Setup cipher for document decryption
        val cipher = setupDocumentCipher()
        val cryptoObject = BiometricPrompt.CryptoObject(cipher)
        
        // ok: kotlin-biometric-authentication
        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }
}
// {/fact}

// Helper functions (implementations would be provided in a real app)
private fun getCipher(): Cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + 
                                                   KeyProperties.BLOCK_MODE_CBC + "/" + 
                                                   KeyProperties.ENCRYPTION_PADDING_PKCS7)

private fun getSignature(): Signature = Signature.getInstance("SHA256withECDSA")

private fun getMac(): Mac = Mac.getInstance("HmacSHA256")

private fun initCipher(): Cipher = getCipher()

private fun setupPaymentCipher(): Cipher = getCipher()

private fun setupFileCipher(): Cipher = getCipher()

private fun setupAppMac(): Mac = getMac()

private fun setupLoginCipher(): Cipher = getCipher()

private fun setupHealthDataCipher(): Cipher = getCipher()

private fun setupFinancialDataSignature(): Signature = getSignature()

private fun setupSettingsMac(): Mac = getMac()

private fun setupPasswordCipher(): Cipher = getCipher()

private fun setupDocumentCipher(): Cipher = getCipher()

private fun initializeNotesCipher(): Cipher = getCipher()

private fun decryptWithCipher(cipher: Cipher) {}

private fun signDataWithSignature(signature: Signature) {}

private fun verifyDataWithMac(mac: Mac) {}

private fun decryptData(cipher: Cipher): String = "decrypted data"

private fun showProtectedContent() {}

private fun showProtectedContent(data: String) {}

private fun processPayment() {}

private fun processPaymentSecurely(cipher: Cipher) {}

private fun accessSensitiveData() {}

private fun decryptSensitiveData() {}

private fun performSensitiveTransaction() {}

private fun grantAccess() {}

private fun accessSecureNotes() {}

private fun accessSecureNotesWithEncryption(cipher: Cipher) {}

private fun accessEncryptedFiles() {}

private fun accessEncryptedFilesSecurely(cipher: Cipher) {}

private fun unlockApp() {}

private fun unlockAppSecurely(mac: Mac) {}

private fun loginUser() {}

private fun loginUserSecurely(cipher: Cipher) {}

private fun accessHealthData() {}

private fun accessHealthDataSecurely(cipher: Cipher) {}

private fun accessFinancialData() {}

private fun accessFinancialDataSecurely(signature: Signature) {}

private fun openSecureSettings() {}

private fun openSecureSettingsWithMac(mac: Mac) {}

private fun showStoredPasswords() {}

private fun showStoredPasswordsSecurely(cipher: Cipher) {}

private fun openDocumentVault() {}

private fun openDocumentVaultSecurely(cipher: Cipher) {}