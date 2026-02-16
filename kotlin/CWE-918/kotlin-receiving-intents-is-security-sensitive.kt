package com.example.securitysensitiveintents

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.app.Activity
import android.content.pm.PackageManager
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.localbroadcastmanager.content.LocalBroadcastManager

// True Positives (Vulnerable Code)

// {fact rule=server-side-request-forgery@v1.0 defects=1}
fun bad_case_1(context: Context) {
    val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val data = intent.getStringExtra("data")
            // Process data without validation
        }
    }
    
    val filter = IntentFilter("com.example.VULNERABLE_ACTION")
    // ruleid: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(receiver, filter)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
fun bad_case_2(context: Context) {
    class VulnerableReceiver : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val command = intent.getStringExtra("command")
            Runtime.getRuntime().exec(command)
        }
    }
    
    val filter = IntentFilter("com.example.EXECUTE_COMMAND")
    // ruleid: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(VulnerableReceiver(), filter)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
fun bad_case_3(context: Context) {
    val dynamicReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val url = intent.getStringExtra("url")
            // Download from URL without validation
        }
    }
    
    val intentFilter = IntentFilter()
    intentFilter.addAction("com.example.DOWNLOAD_ACTION")
    intentFilter.addCategory(Intent.CATEGORY_DEFAULT)
    
    // ruleid: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(dynamicReceiver, intentFilter)
}
// {/fact}

class BadActivity : Activity() {
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val message = intent.getStringExtra("message")
            // Process message without validation
        }
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val filter = IntentFilter("com.example.MESSAGE_ACTION")
        // ruleid: kotlin-receiving-intents-is-security-sensitive
        registerReceiver(receiver, filter)
    }
    
    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(receiver)
    }
}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
fun bad_case_5(context: Context) {
    val sensitiveDataReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val username = intent.getStringExtra("username")
            val password = intent.getStringExtra("password")
            // Store credentials without validation
        }
    }
    
    val filter = IntentFilter("com.example.LOGIN_ACTION")
    // ruleid: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(sensitiveDataReceiver, filter, Context.RECEIVER_EXPORTED)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
fun bad_case_6(context: Context) {
    val multiActionReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                "com.example.ACTION1" -> {
                    val data = intent.getStringExtra("data")
                    // Process data
                }
                "com.example.ACTION2" -> {
                    val command = intent.getStringExtra("command")
                    // Execute command
                }
            }
        }
    }
    
    val filter = IntentFilter()
    filter.addAction("com.example.ACTION1")
    filter.addAction("com.example.ACTION2")
    
    // ruleid: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(multiActionReceiver, filter)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
fun bad_case_7(context: Context) {
    val dataReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val bundle = intent.extras
            if (bundle != null) {
                val data = bundle.getString("data")
                // Process data without validation
            }
        }
    }
    
    val filter = IntentFilter("com.example.DATA_ACTION")
    // ruleid: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(dataReceiver, filter)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
fun bad_case_8(context: Context) {
    val priorityReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val action = intent.action
            if (action == "com.example.HIGH_PRIORITY_ACTION") {
                val data = intent.getStringExtra("data")
                // Process high priority data
            }
        }
    }
    
    val filter = IntentFilter("com.example.HIGH_PRIORITY_ACTION")
    filter.priority = 100 // High priority
    
    // ruleid: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(priorityReceiver, filter)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
fun bad_case_9(context: Context) {
    val configReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val configKey = intent.getStringExtra("key")
            val configValue = intent.getStringExtra("value")
            // Update app configuration without validation
        }
    }
    
    val filter = IntentFilter("com.example.UPDATE_CONFIG")
    // ruleid: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(configReceiver, filter, Context.RECEIVER_VISIBLE_TO_INSTANT_APPS)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
fun bad_case_10(context: Context) {
    val conditionalReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.hasExtra("data")) {
                val data = intent.getStringExtra("data")
                // Process data without validation
            }
        }
    }
    
    if (System.currentTimeMillis() % 2 == 0L) {
        val filter = IntentFilter("com.example.CONDITIONAL_ACTION")
        // ruleid: kotlin-receiving-intents-is-security-sensitive
        context.registerReceiver(conditionalReceiver, filter)
    }
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
fun bad_case_11(context: Context) {
    val fileReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val filePath = intent.getStringExtra("path")
            // Access file without validation
        }
    }
    
    val filter = IntentFilter("com.example.FILE_ACTION")
    filter.addDataScheme("file")
    
    // ruleid: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(fileReceiver, filter)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
fun bad_case_12(context: Context) {
    val urlReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val url = intent.getStringExtra("url")
            // Process URL without validation
        }
    }
    
    val filter = IntentFilter("com.example.URL_ACTION")
    filter.addDataScheme("http")
    filter.addDataScheme("https")
    
    // ruleid: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(urlReceiver, filter)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
fun bad_case_13(context: Context) {
    val customSchemeReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val data = intent.dataString
            // Process custom scheme data without validation
        }
    }
    
    val filter = IntentFilter("com.example.CUSTOM_SCHEME")
    filter.addDataScheme("myapp")
    
    // ruleid: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(customSchemeReceiver, filter)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
fun bad_case_14(context: Context) {
    val mimeTypeReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val type = intent.type
            // Process MIME type data without validation
        }
    }
    
    val filter = IntentFilter("com.example.MIME_ACTION")
    filter.addDataType("text/plain")
    
    // ruleid: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(mimeTypeReceiver, filter)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
fun bad_case_15(context: Context) {
    val categoryReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val categories = intent.categories
            // Process categories without validation
        }
    }
    
    val filter = IntentFilter("com.example.CATEGORY_ACTION")
    filter.addCategory(Intent.CATEGORY_DEFAULT)
    filter.addCategory(Intent.CATEGORY_BROWSABLE)
    
    // ruleid: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(categoryReceiver, filter)
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=server-side-request-forgery@v1.0 defects=0}
fun good_case_1(context: Context) {
    val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val data = intent.getStringExtra("data")
            // Process data
        }
    }
    
    val filter = IntentFilter("com.example.SECURE_ACTION")
    // ok: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(receiver, filter, "com.example.CUSTOM_PERMISSION", null)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
fun good_case_2(context: Context) {
    class SecureReceiver : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val command = intent.getStringExtra("command")
            // Validate and execute command
        }
    }
    
    val filter = IntentFilter("com.example.SECURE_COMMAND")
    // ok: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(SecureReceiver(), filter, "com.example.EXECUTE_PERMISSION", null)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
fun good_case_3(context: Context) {
    val localReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val message = intent.getStringExtra("message")
            // Process local message
        }
    }
    
    val filter = IntentFilter("com.example.LOCAL_ACTION")
    // ok: kotlin-receiving-intents-is-security-sensitive
    LocalBroadcastManager.getInstance(context).registerReceiver(localReceiver, filter)
}
// {/fact}

class GoodActivity : Activity() {
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val message = intent.getStringExtra("message")
            // Process message
        }
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val filter = IntentFilter("com.example.SECURE_MESSAGE")
        // ok: kotlin-receiving-intents-is-security-sensitive
        registerReceiver(receiver, filter, "com.example.MESSAGE_PERMISSION", null)
    }
    
    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(receiver)
    }
}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
fun good_case_5(context: Context) {
    val secureDataReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val username = intent.getStringExtra("username")
            val password = intent.getStringExtra("password")
            // Validate and store credentials
        }
    }
    
    val filter = IntentFilter("com.example.SECURE_LOGIN")
    // ok: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(secureDataReceiver, filter, "com.example.LOGIN_PERMISSION", null)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
fun good_case_6(context: Context) {
    val multiActionReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                "com.example.SECURE_ACTION1" -> {
                    val data = intent.getStringExtra("data")
                    // Process data
                }
                "com.example.SECURE_ACTION2" -> {
                    val command = intent.getStringExtra("command")
                    // Execute command
                }
            }
        }
    }
    
    val filter = IntentFilter()
    filter.addAction("com.example.SECURE_ACTION1")
    filter.addAction("com.example.SECURE_ACTION2")
    
    // ok: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(multiActionReceiver, filter, "com.example.MULTI_PERMISSION", null)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
fun good_case_7(context: Context) {
    val dataReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val bundle = intent.extras
            if (bundle != null) {
                val data = bundle.getString("data")
                // Process data
            }
        }
    }
    
    // Using LocalBroadcastManager for internal app communication
    val filter = IntentFilter("com.example.INTERNAL_DATA")
    // ok: kotlin-receiving-intents-is-security-sensitive
    LocalBroadcastManager.getInstance(context).registerReceiver(dataReceiver, filter)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
fun good_case_8(context: Context) {
    val priorityReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val action = intent.action
            if (action == "com.example.SECURE_PRIORITY") {
                val data = intent.getStringExtra("data")
                // Process high priority data
            }
        }
    }
    
    val filter = IntentFilter("com.example.SECURE_PRIORITY")
    filter.priority = 100 // High priority
    
    // ok: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(priorityReceiver, filter, "com.example.PRIORITY_PERMISSION", null)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
fun good_case_9(context: Context) {
    val configReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val configKey = intent.getStringExtra("key")
            val configValue = intent.getStringExtra("value")
            // Update app configuration
        }
    }
    
    // Using LocalBroadcastManager for configuration updates
    val filter = IntentFilter("com.example.INTERNAL_CONFIG")
    // ok: kotlin-receiving-intents-is-security-sensitive
    LocalBroadcastManager.getInstance(context).registerReceiver(configReceiver, filter)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
fun good_case_10(context: Context) {
    val conditionalReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.hasExtra("data")) {
                val data = intent.getStringExtra("data")
                // Process data
            }
        }
    }
    
    if (System.currentTimeMillis() % 2 == 0L) {
        val filter = IntentFilter("com.example.SECURE_CONDITIONAL")
        // ok: kotlin-receiving-intents-is-security-sensitive
        context.registerReceiver(conditionalReceiver, filter, "com.example.CONDITIONAL_PERMISSION", null)
    }
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
fun good_case_11(context: Context) {
    val fileReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val filePath = intent.getStringExtra("path")
            // Access file with validation
        }
    }
    
    val filter = IntentFilter("com.example.SECURE_FILE")
    filter.addDataScheme("file")
    
    // ok: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(fileReceiver, filter, "com.example.FILE_PERMISSION", null)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
fun good_case_12(context: Context) {
    val urlReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val url = intent.getStringExtra("url")
            // Process URL with validation
        }
    }
    
    // Using LocalBroadcastManager for URL processing
    val filter = IntentFilter("com.example.INTERNAL_URL")
    filter.addDataScheme("http")
    filter.addDataScheme("https")
    
    // ok: kotlin-receiving-intents-is-security-sensitive
    LocalBroadcastManager.getInstance(context).registerReceiver(urlReceiver, filter)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
fun good_case_13(context: Context) {
    val customSchemeReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val data = intent.dataString
            // Process custom scheme data with validation
        }
    }
    
    val filter = IntentFilter("com.example.SECURE_SCHEME")
    filter.addDataScheme("myapp")
    
    // ok: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(customSchemeReceiver, filter, "com.example.SCHEME_PERMISSION", null)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
fun good_case_14(context: Context) {
    val mimeTypeReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val type = intent.type
            // Process MIME type data with validation
        }
    }
    
    val filter = IntentFilter("com.example.SECURE_MIME")
    filter.addDataType("text/plain")
    
    // ok: kotlin-receiving-intents-is-security-sensitive
    context.registerReceiver(mimeTypeReceiver, filter, "com.example.MIME_PERMISSION", null)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
fun good_case_15(context: Context) {
    val categoryReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val categories = intent.categories
            // Process categories with validation
        }
    }
    
    // Using LocalBroadcastManager for category processing
    val filter = IntentFilter("com.example.INTERNAL_CATEGORY")
    filter.addCategory(Intent.CATEGORY_DEFAULT)
    filter.addCategory(Intent.CATEGORY_BROWSABLE)
    
    // ok: kotlin-receiving-intents-is-security-sensitive
    LocalBroadcastManager.getInstance(context).registerReceiver(categoryReceiver, filter)
}
// {/fact}