// File: NullPointerDereferenceExamples.kt

import java.io.File
import java.util.HashMap
import java.util.ArrayList
import java.util.concurrent.ConcurrentHashMap

// True Positive Examples (Vulnerable Code)

// {fact rule=inconsistent-null-check@v1.0 defects=1}
fun bad_case_1() {
    var name: String? = null
    // ruleid: kotlin-null-pointer-dereference
    val length = name.length // Direct dereference of nullable variable without null check
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
fun bad_case_2() {
    val userMap: HashMap<String, String>? = null
    // ruleid: kotlin-null-pointer-dereference
    val size = userMap.size // Dereferencing a null map
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
fun bad_case_3() {
    var user: User? = null
    // ruleid: kotlin-null-pointer-dereference
    println("User name: ${user.name}") // Accessing property of null object
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
fun bad_case_4() {
    val numbers: List<Int>? = null
    // ruleid: kotlin-null-pointer-dereference
    for (num in numbers) { // Iterating over null collection
        println(num)
    }
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
fun bad_case_5() {
    var file: File? = null
    try {
        // ruleid: kotlin-null-pointer-dereference
        file.readText() // Calling method on null object
    } catch (e: Exception) {
        println("Error reading file")
    }
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
fun bad_case_6() {
    var config: Configuration? = null
    if (System.currentTimeMillis() % 2 == 0L) {
        config = Configuration()
    }
    // ruleid: kotlin-null-pointer-dereference
    val timeout = config.timeout // Potential null dereference after conditional initialization
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
fun bad_case_7() {
    var data: String? = null
    var isValid = false
    
    if (isValid) {
        data = "Valid data"
    }
    
    // ruleid: kotlin-null-pointer-dereference
    println(data.uppercase()) // Dereferencing potentially null variable
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
fun bad_case_8() {
    val array: Array<String>? = null
    // ruleid: kotlin-null-pointer-dereference
    val firstElement = array[0] // Accessing element of null array
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
fun bad_case_9() {
    var processor: DataProcessor? = null
    val data = "raw data"
    
    // ruleid: kotlin-null-pointer-dereference
    processor.process(data) // Calling method on uninitialized object
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
fun bad_case_10() {
    class Container {
        var items: List<String>? = null
    }
    
    val container = Container()
    // ruleid: kotlin-null-pointer-dereference
    println("First item: ${container.items.first()}") // Dereferencing nullable property without check
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
fun bad_case_11() {
    var manager: ResourceManager? = null
    try {
        if (false) { // This condition is always false
            manager = ResourceManager()
        }
        // ruleid: kotlin-null-pointer-dereference
        manager.close() // Dereferencing definitely null object
    } finally {
        println("Operation completed")
    }
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
fun bad_case_12() {
    val map = HashMap<String, String?>()
    map["key"] = null
    val value = map["key"]
    // ruleid: kotlin-null-pointer-dereference
    println(value.length) // Dereferencing a value that is null
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
fun bad_case_13() {
    var callback: (() -> Unit)? = null
    // ruleid: kotlin-null-pointer-dereference
    callback() // Invoking null function reference
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
fun bad_case_14() {
    var service: NetworkService? = null
    val isConnected = true
    
    if (!isConnected) {
        service = NetworkService()
    }
    
    // ruleid: kotlin-null-pointer-dereference
    service.connect() // Service is null because condition is false
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
fun bad_case_15() {
    class Node {
        var next: Node? = null
    }
    
    val head: Node? = null
    // ruleid: kotlin-null-pointer-dereference
    val nextNode = head.next // Accessing property of null node
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=inconsistent-null-check@v1.0 defects=0}
fun good_case_1() {
    var name: String? = null
    // ok: kotlin-null-pointer-dereference
    val length = name?.length ?: 0 // Safe call with elvis operator
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
fun good_case_2() {
    val userMap: HashMap<String, String>? = null
    // ok: kotlin-null-pointer-dereference
    val size = userMap?.size ?: 0 // Safe call with default value
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
fun good_case_3() {
    var user: User? = null
    // ok: kotlin-null-pointer-dereference
    println("User name: ${user?.name ?: "Unknown"}") // Safe property access with default
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
fun good_case_4() {
    val numbers: List<Int>? = null
    // ok: kotlin-null-pointer-dereference
    numbers?.forEach { num ->
        println(num)
    } // Safe iteration with null check
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
fun good_case_5() {
    var file: File? = null
    try {
        // ok: kotlin-null-pointer-dereference
        file?.readText() // Safe method call
    } catch (e: Exception) {
        println("Error reading file")
    }
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
fun good_case_6() {
    var config: Configuration? = null
    if (System.currentTimeMillis() % 2 == 0L) {
        config = Configuration()
    }
    // ok: kotlin-null-pointer-dereference
    if (config != null) {
        val timeout = config.timeout // Explicit null check before dereference
    }
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
fun good_case_7() {
    var data: String? = null
    var isValid = false
    
    if (isValid) {
        data = "Valid data"
    }
    
    // ok: kotlin-null-pointer-dereference
    data?.let {
        println(it.uppercase()) // Using let for safe execution
    }
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
fun good_case_8() {
    val array: Array<String>? = null
    // ok: kotlin-null-pointer-dereference
    val firstElement = array?.getOrNull(0) // Safe array access
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
fun good_case_9() {
    var processor: DataProcessor? = null
    val data = "raw data"
    
    // ok: kotlin-null-pointer-dereference
    processor?.process(data) ?: run {
        println("Processor not initialized")
    } // Safe method call with alternative action
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
fun good_case_10() {
    class Container {
        var items: List<String>? = null
    }
    
    val container = Container()
    // ok: kotlin-null-pointer-dereference
    println("First item: ${container.items?.firstOrNull() ?: "No items"}") // Safe property access
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
fun good_case_11() {
    var manager: ResourceManager? = null
    try {
        if (false) {
            manager = ResourceManager()
        }
        // ok: kotlin-null-pointer-dereference
        manager?.close() // Safe method call on potentially null object
    } finally {
        println("Operation completed")
    }
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
fun good_case_12() {
    val map = HashMap<String, String?>()
    map["key"] = null
    val value = map["key"]
    // ok: kotlin-null-pointer-dereference
    println(value?.length ?: "null value") // Safe dereference with elvis operator
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
fun good_case_13() {
    var callback: (() -> Unit)? = null
    // ok: kotlin-null-pointer-dereference
    callback?.invoke() // Safe function invocation
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
fun good_case_14() {
    var service: NetworkService? = null
    val isConnected = true
    
    if (!isConnected) {
        service = NetworkService()
    }
    
    // ok: kotlin-null-pointer-dereference
    if (service != null) {
        service.connect() // Explicit null check before method call
    } else {
        println("Service not initialized")
    }
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
fun good_case_15() {
    class Node {
        var next: Node? = null
    }
    
    val head: Node? = null
    // ok: kotlin-null-pointer-dereference
    val nextNode = head?.next // Safe property access
}
// {/fact}

// Helper classes for the examples
class User {
    val name: String = "John"
}

class Configuration {
    val timeout: Int = 30
}

class DataProcessor {
    fun process(data: String) {
        println("Processing: $data")
    }
}

class ResourceManager {
    fun close() {
        println("Resources released")
    }
}

class NetworkService {
    fun connect() {
        println("Connected to network")
    }
}