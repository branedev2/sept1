import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.io.IOException
import java.io.File
import kotlin.concurrent.thread
import java.net.URL
import java.util.concurrent.Future
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.atomic.AtomicInteger

// True Positives (Vulnerable Code Examples)

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_1() {
    val executor = Executors.newFixedThreadPool(10)
    
    try {
        executor.submit { 
            println("Task 1 executed")
        }
        
        val result = 10 / 0 // This will throw ArithmeticException
        
        // ruleid: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // This might not be executed due to exception above
    } catch (e: Exception) {
        println("Exception caught: ${e.message}")
        // No shutdown in catch block
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_2() {
    val executor = Executors.newCachedThreadPool()
    
    val file = File("nonexistent.txt")
    
    try {
        executor.submit { 
            println("Processing file")
        }
        
        val content = file.readText() // May throw IOException
        
        // ruleid: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // This might not be executed due to exception above
    } catch (e: IOException) {
        println("File error: ${e.message}")
        // Missing executor shutdown
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_3() {
    val executor = Executors.newSingleThreadExecutor()
    
    try {
        val url = URL("https://example.com")
        executor.submit {
            println("Connecting to URL")
        }
        
        val connection = url.openConnection()
        connection.connect() // May throw IOException
        
        // ruleid: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // This might not be executed due to exception above
    } catch (e: Exception) {
        println("Connection error: ${e.message}")
        // No shutdown in exception handler
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_4() {
    val executor = Executors.newWorkStealingPool()
    
    try {
        executor.submit {
            println("Task executing")
        }
        
        val list = listOf(1, 2, 3)
        val item = list[5] // Will throw IndexOutOfBoundsException
        
        // ruleid: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // This might not be executed due to exception above
    } catch (e: IndexOutOfBoundsException) {
        println("Index error: ${e.message}")
        // Missing executor shutdown
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_5() {
    val executor = Executors.newFixedThreadPool(4)
    
    try {
        executor.submit {
            println("Background task")
        }
        
        val map = mapOf("key1" to "value1")
        val value = map["nonexistent"]!!.toString() // Will throw NullPointerException
        
        // ruleid: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // This might not be executed due to exception above
    } catch (e: NullPointerException) {
        println("Null error: ${e.message}")
        // No shutdown in catch block
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_6() {
    val scheduledExecutor = Executors.newScheduledThreadPool(2)
    
    try {
        scheduledExecutor.schedule({
            println("Scheduled task")
        }, 1, TimeUnit.SECONDS)
        
        val arr = IntArray(3)
        val value = arr[10] // Will throw ArrayIndexOutOfBoundsException
        
        // ruleid: kotlin-improper-shutdown-of-executor-service
        scheduledExecutor.shutdown() // This might not be executed due to exception above
    } catch (e: Exception) {
        println("Array error: ${e.message}")
        // Missing executor shutdown
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_7() {
    val executor = ThreadPoolExecutor(
        2, 4, 60L, TimeUnit.SECONDS, LinkedBlockingQueue()
    )
    
    try {
        executor.submit {
            println("Custom executor task")
        }
        
        val str: String? = null
        val length = str!!.length // Will throw NullPointerException
        
        // ruleid: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // This might not be executed due to exception above
    } catch (e: Exception) {
        println("Error: ${e.message}")
        // No shutdown in catch block
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_8() {
    val executor = Executors.newSingleThreadExecutor()
    
    try {
        executor.submit {
            println("Task in progress")
        }
        
        val obj: Any = "string"
        val num = obj as Int // Will throw ClassCastException
        
        // ruleid: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // This might not be executed due to exception above
    } catch (e: ClassCastException) {
        println("Cast error: ${e.message}")
        // Missing executor shutdown
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_9() {
    val executor: ExecutorService = Executors.newFixedThreadPool(3)
    val futures = mutableListOf<Future<*>>()
    
    try {
        for (i in 1..5) {
            futures.add(executor.submit {
                if (i == 3) throw RuntimeException("Task $i failed")
                println("Task $i completed")
            })
        }
        
        for (future in futures) {
            future.get() // Will throw ExecutionException
        }
        
        // ruleid: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // This might not be executed due to exception above
    } catch (e: Exception) {
        println("Task execution error: ${e.message}")
        // No shutdown in catch block
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_10() {
    val executor = Executors.newCachedThreadPool()
    
    try {
        executor.execute {
            println("Executing task")
        }
        
        val resource = File("locked_resource.txt")
        if (!resource.exists()) {
            throw IOException("Resource not found")
        }
        
        // ruleid: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // This might not be executed due to exception above
    } catch (e: IOException) {
        println("Resource error: ${e.message}")
        // Missing executor shutdown
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_11() {
    val counter = AtomicInteger(0)
    val executor = Executors.newFixedThreadPool(2)
    
    try {
        executor.submit {
            counter.incrementAndGet()
        }
        
        if (counter.get() < 0) {
            throw IllegalStateException("Invalid counter state")
        }
        
        // ruleid: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // This might not be executed due to exception above
    } catch (e: IllegalStateException) {
        println("State error: ${e.message}")
        // No shutdown in catch block
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_12() {
    val executor: ScheduledExecutorService = Executors.newScheduledThreadPool(1)
    
    try {
        executor.scheduleAtFixedRate({
            println("Periodic task")
        }, 0, 1, TimeUnit.SECONDS)
        
        Thread.sleep(1000)
        
        if (System.currentTimeMillis() % 2 == 0) {
            throw RuntimeException("Random failure")
        }
        
        // ruleid: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // This might not be executed due to exception above
    } catch (e: RuntimeException) {
        println("Runtime error: ${e.message}")
        // Missing executor shutdown
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_13() {
    val executor = Executors.newWorkStealingPool(4)
    
    try {
        executor.submit {
            println("Work stealing task")
        }
        
        val config = HashMap<String, String>()
        val setting = config["database"]!!.toString() // Will throw NullPointerException
        
        // ruleid: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // This might not be executed due to exception above
    } catch (e: Exception) {
        println("Configuration error: ${e.message}")
        // No shutdown in catch block
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_14() {
    val executor = Executors.newFixedThreadPool(2)
    
    try {
        executor.submit {
            println("Processing task")
        }
        
        val data = ByteArray(1024)
        val file = File("nonexistent/path/file.dat")
        file.writeBytes(data) // May throw IOException
        
        // ruleid: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // This might not be executed due to exception above
    } catch (e: IOException) {
        println("File write error: ${e.message}")
        // Missing executor shutdown
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_15() {
    val executor = Executors.newSingleThreadExecutor()
    
    try {
        executor.submit {
            println("Background processing")
        }
        
        val text = "123abc"
        val number = text.toInt() // Will throw NumberFormatException
        
        // ruleid: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // This might not be executed due to exception above
    } catch (e: NumberFormatException) {
        println("Parse error: ${e.message}")
        // No shutdown in catch block
    }
}
// {/fact}

// True Negatives (Safe Code Examples)

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_1() {
    val executor = Executors.newFixedThreadPool(10)
    
    try {
        executor.submit { 
            println("Task 1 executed")
        }
        
        val result = 10 / 0 // This will throw ArithmeticException
        
        executor.shutdown()
    } catch (e: Exception) {
        println("Exception caught: ${e.message}")
        // ok: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // Properly shutting down in catch block
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_2() {
    val executor = Executors.newCachedThreadPool()
    
    try {
        executor.submit { 
            println("Processing file")
        }
        
        val file = File("nonexistent.txt")
        val content = file.readText() // May throw IOException
        
        executor.shutdown()
    } catch (e: IOException) {
        println("File error: ${e.message}")
        // ok: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // Properly shutting down in catch block
    } finally {
        if (!executor.isShutdown) {
            executor.shutdown()
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_3() {
    val executor = Executors.newSingleThreadExecutor()
    
    try {
        val url = URL("https://example.com")
        executor.submit {
            println("Connecting to URL")
        }
        
        val connection = url.openConnection()
        connection.connect() // May throw IOException
        
        executor.shutdown()
    } catch (e: Exception) {
        println("Connection error: ${e.message}")
    } finally {
        // ok: kotlin-improper-shutdown-of-executor-service
        if (!executor.isShutdown) {
            executor.shutdown() // Properly shutting down in finally block
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_4() {
    val executor = Executors.newWorkStealingPool()
    
    try {
        executor.submit {
            println("Task executing")
        }
        
        val list = listOf(1, 2, 3)
        val item = list.getOrNull(5) ?: 0 // Safe access
        
        // ok: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // Will be executed as no exception is thrown
    } finally {
        if (!executor.isShutdown) {
            executor.shutdown()
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_5() {
    val executor = Executors.newFixedThreadPool(4)
    
    try {
        executor.submit {
            println("Background task")
        }
        
        val map = mapOf("key1" to "value1")
        val value = map["nonexistent"] ?: "default" // Safe access
        
        // ok: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // Will be executed as no exception is thrown
    } catch (e: Exception) {
        println("Error: ${e.message}")
        executor.shutdown()
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_6() {
    val scheduledExecutor = Executors.newScheduledThreadPool(2)
    
    try {
        scheduledExecutor.schedule({
            println("Scheduled task")
        }, 1, TimeUnit.SECONDS)
        
        val arr = IntArray(3)
        val index = 10
        
        if (index < arr.size) {
            val value = arr[index]
        }
        
        scheduledExecutor.shutdown()
    } catch (e: Exception) {
        println("Array error: ${e.message}")
        scheduledExecutor.shutdown()
    } finally {
        // ok: kotlin-improper-shutdown-of-executor-service
        if (!scheduledExecutor.isShutdown) {
            scheduledExecutor.shutdown() // Properly shutting down in finally block
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_7() {
    val executor = ThreadPoolExecutor(
        2, 4, 60L, TimeUnit.SECONDS, LinkedBlockingQueue()
    )
    
    try {
        executor.submit {
            println("Custom executor task")
        }
        
        val str: String? = null
        val length = str?.length ?: 0 // Safe null handling
        
        // ok: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // Will be executed as no exception is thrown
    } finally {
        if (!executor.isShutdown) {
            executor.shutdownNow()
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_8() {
    val executor = Executors.newSingleThreadExecutor()
    
    try {
        executor.submit {
            println("Task in progress")
        }
        
        val obj: Any = "string"
        
        if (obj is Int) {
            val num = obj // Safe cast
        }
        
        // ok: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // Will be executed as no exception is thrown
    } catch (e: Exception) {
        executor.shutdown()
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_9() {
    val executor: ExecutorService = Executors.newFixedThreadPool(3)
    
    try {
        for (i in 1..5) {
            executor.submit {
                println("Task $i executing")
            }
        }
    } finally {
        // ok: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // Always executed in finally block
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow()
            }
        } catch (e: InterruptedException) {
            executor.shutdownNow()
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_10() {
    val executor = Executors.newCachedThreadPool()
    
    try {
        executor.execute {
            println("Executing task")
        }
        
        val resource = File("locked_resource.txt")
        if (!resource.exists()) {
            println("Resource not found")
        }
        
        // ok: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // Will be executed as no exception is thrown
    } catch (e: Exception) {
        executor.shutdown()
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_11() {
    val counter = AtomicInteger(0)
    val executor = Executors.newFixedThreadPool(2)
    
    try {
        executor.submit {
            counter.incrementAndGet()
        }
    } finally {
        // ok: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // Always executed in finally block
        if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
            executor.shutdownNow()
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_12() {
    val executor: ScheduledExecutorService = Executors.newScheduledThreadPool(1)
    
    try {
        executor.scheduleAtFixedRate({
            println("Periodic task")
        }, 0, 1, TimeUnit.SECONDS)
        
        Thread.sleep(1000)
    } catch (e: Exception) {
        println("Error: ${e.message}")
    } finally {
        // ok: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // Always executed in finally block
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_13() {
    val executor = Executors.newWorkStealingPool(4)
    
    try {
        executor.submit {
            println("Work stealing task")
        }
        
        val config = HashMap<String, String>()
        val setting = config["database"] ?: "default" // Safe access
        
        // ok: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // Will be executed as no exception is thrown
    } catch (e: Exception) {
        executor.shutdown()
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_14() {
    val executor = Executors.newFixedThreadPool(2)
    
    try {
        executor.submit {
            println("Processing task")
        }
        
        val data = ByteArray(1024)
        val file = File("output.dat")
        
        try {
            file.writeBytes(data)
        } catch (e: IOException) {
            println("File write error: ${e.message}")
        }
        
        // ok: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // Will be executed as exception is handled
    } finally {
        if (!executor.isShutdown) {
            executor.shutdownNow()
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_15() {
    val executor = Executors.newSingleThreadExecutor()
    
    val shutdownHook = Thread {
        // ok: kotlin-improper-shutdown-of-executor-service
        executor.shutdown() // Shutdown hook ensures executor is shut down
        try {
            if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                executor.shutdownNow()
            }
        } catch (e: InterruptedException) {
            executor.shutdownNow()
        }
    }
    
    Runtime.getRuntime().addShutdownHook(shutdownHook)
    
    try {
        executor.submit {
            println("Background processing")
        }
        
        val text = "123abc"
        val number = text.toIntOrNull() ?: 0 // Safe conversion
    } catch (e: Exception) {
        println("Error: ${e.message}")
        executor.shutdown()
    }
}
// {/fact}