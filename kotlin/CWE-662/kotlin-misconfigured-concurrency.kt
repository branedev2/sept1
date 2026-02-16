import java.util.concurrent.*
import kotlinx.coroutines.*
import kotlin.concurrent.thread

// True Positives (Vulnerable Code)

// {fact rule=misconfigured-concurrency@v1.0 defects=1}
fun bad_case_1() {
    val executor = Executors.newSingleThreadExecutor()
    val future = executor.submit<String> {
        Thread.sleep(5000)
        "Result after processing"
    }
    
    try {
        // ruleid: kotlin-misconfigured-concurrency
        val result = future.get() // No timeout specified, could block indefinitely
        println("Result: $result")
    } catch (e: Exception) {
        println("Error: ${e.message}")
    } finally {
        executor.shutdown()
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=1}
fun bad_case_2() {
    val completableFuture = CompletableFuture.supplyAsync {
        // Simulate a long-running operation that might hang
        Thread.sleep(10000)
        "Operation completed"
    }
    
    try {
        // ruleid: kotlin-misconfigured-concurrency
        val result = completableFuture.get() // Missing timeout, vulnerable to indefinite blocking
        println("Got result: $result")
    } catch (e: Exception) {
        println("Exception occurred: ${e.message}")
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=1}
fun bad_case_3() {
    val executor = Executors.newFixedThreadPool(2)
    
    val task1 = executor.submit<Int> {
        // This task might never complete if there's an issue
        while (true) {
            if (someConditionThatMightNeverBeMet()) break
            Thread.sleep(100)
        }
        42
    }
    
    try {
        // ruleid: kotlin-misconfigured-concurrency
        val result = task1.get() // Will block forever if the condition is never met
        println("Task completed with result: $result")
    } catch (e: Exception) {
        println("Task failed: ${e.message}")
    } finally {
        executor.shutdown()
    }
}
// {/fact}

fun someConditionThatMightNeverBeMet(): Boolean {
    return Math.random() < 0.001 // Very unlikely to be true
}

// {fact rule=misconfigured-concurrency@v1.0 defects=1}
fun bad_case_4() {
    val cf1 = CompletableFuture.supplyAsync {
        // Simulate network call that might hang
        Thread.sleep(3000)
        "Data from service 1"
    }
    
    val cf2 = CompletableFuture.supplyAsync {
        // Simulate database query that might hang
        Thread.sleep(2000)
        "Data from service 2"
    }
    
    try {
        // ruleid: kotlin-misconfigured-concurrency
        val result1 = cf1.get() // No timeout
        // ruleid: kotlin-misconfigured-concurrency
        val result2 = cf2.get() // No timeout
        println("Combined results: $result1 and $result2")
    } catch (e: Exception) {
        println("Error in processing: ${e.message}")
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=1}
fun bad_case_5() {
    val executor = Executors.newCachedThreadPool()
    val callables = mutableListOf<Callable<String>>()
    
    for (i in 1..5) {
        callables.add(Callable {
            Thread.sleep(1000 * i)
            "Result $i"
        })
    }
    
    val futures = executor.invokeAll(callables)
    
    try {
        for (future in futures) {
            // ruleid: kotlin-misconfigured-concurrency
            val result = future.get() // No timeout for any of the futures
            println("Got: $result")
        }
    } catch (e: Exception) {
        println("Error: ${e.message}")
    } finally {
        executor.shutdown()
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=1}
fun bad_case_6() {
    val completableFuture = CompletableFuture<String>()
    
    // Start a thread that might never complete the future
    thread {
        try {
            // Simulating a task that might hang
            Thread.sleep(Long.MAX_VALUE)
            completableFuture.complete("This will never happen")
        } catch (e: InterruptedException) {
            completableFuture.completeExceptionally(e)
        }
    }
    
    try {
        // ruleid: kotlin-misconfigured-concurrency
        val result = completableFuture.get() // Will block forever
        println(result)
    } catch (e: Exception) {
        println("Exception: ${e.message}")
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=1}
fun bad_case_7() {
    val executor = Executors.newSingleThreadExecutor()
    
    val future = executor.submit<Int> {
        var sum = 0
        for (i in 1..1_000_000_000) { // Very long computation
            sum += i
        }
        sum
    }
    
    try {
        println("Waiting for result...")
        // ruleid: kotlin-misconfigured-concurrency
        val result = future.get() // No timeout, could block for a very long time
        println("Sum: $result")
    } catch (e: Exception) {
        println("Calculation error: ${e.message}")
    } finally {
        executor.shutdown()
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=1}
fun bad_case_8() {
    val latch = CountDownLatch(1)
    val future = CompletableFuture.supplyAsync {
        try {
            // Wait for latch that might never count down
            latch.await() // This could hang indefinitely
            "Latch released"
        } catch (e: InterruptedException) {
            "Interrupted"
        }
    }
    
    try {
        // ruleid: kotlin-misconfigured-concurrency
        val result = future.get() // No timeout, will block if latch never counts down
        println(result)
    } catch (e: Exception) {
        println("Error: ${e.message}")
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=1}
fun bad_case_9() {
    val executor = Executors.newSingleThreadExecutor()
    
    val future = executor.submit<String> {
        // Simulate a deadlock scenario
        val lock1 = Object()
        val lock2 = Object()
        
        thread {
            synchronized(lock1) {
                Thread.sleep(100)
                synchronized(lock2) {
                    println("Thread 1 acquired both locks")
                }
            }
        }
        
        synchronized(lock2) {
            Thread.sleep(100)
            synchronized(lock1) {
                println("Thread 2 acquired both locks")
            }
        }
        
        "This will never be returned due to deadlock"
    }
    
    try {
        // ruleid: kotlin-misconfigured-concurrency
        val result = future.get() // Will block forever due to deadlock
        println(result)
    } catch (e: Exception) {
        println("Error: ${e.message}")
    } finally {
        executor.shutdown()
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=1}
fun bad_case_10() {
    val completableFuture = CompletableFuture.supplyAsync<String> {
        // Simulate an external service call that might hang
        val socket = java.net.Socket()
        try {
            socket.connect(java.net.InetSocketAddress("example.com", 80), 0) // No connection timeout
            val response = socket.getInputStream().bufferedReader().readLine()
            socket.close()
            response
        } catch (e: Exception) {
            e.message ?: "Unknown error"
        }
    }
    
    try {
        // ruleid: kotlin-misconfigured-concurrency
        val result = completableFuture.get() // No timeout, could hang if network is slow
        println("Response: $result")
    } catch (e: Exception) {
        println("Network error: ${e.message}")
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=1}
fun bad_case_11() {
    val executor = Executors.newFixedThreadPool(4)
    val completionService = ExecutorCompletionService<String>(executor)
    
    for (i in 1..10) {
        completionService.submit {
            Thread.sleep(1000 * i)
            "Task $i completed"
        }
    }
    
    try {
        for (i in 1..10) {
            // ruleid: kotlin-misconfigured-concurrency
            val future = completionService.take() // This is ok, but the next line isn't
            // ruleid: kotlin-misconfigured-concurrency
            val result = future.get() // No timeout
            println(result)
        }
    } catch (e: Exception) {
        println("Error: ${e.message}")
    } finally {
        executor.shutdown()
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=1}
fun bad_case_12() {
    runBlocking {
        val deferredResult = async(Dispatchers.IO) {
            // Simulate a long-running computation
            delay(5000)
            "Async operation completed"
        }
        
        // Convert to Java's CompletableFuture
        val completableFuture = deferredResult.asCompletableFuture()
        
        try {
            // ruleid: kotlin-misconfigured-concurrency
            val result = completableFuture.get() // No timeout
            println("Result: $result")
        } catch (e: Exception) {
            println("Error: ${e.message}")
        }
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=1}
fun bad_case_13() {
    val scheduledExecutor = Executors.newScheduledThreadPool(1)
    
    val future = scheduledExecutor.schedule({
        // Task that might hang
        Thread.sleep(10000)
        "Scheduled task completed"
    }, 1, TimeUnit.SECONDS)
    
    try {
        println("Waiting for scheduled task...")
        // ruleid: kotlin-misconfigured-concurrency
        val result = future.get() // No timeout
        println(result)
    } catch (e: Exception) {
        println("Scheduled task error: ${e.message}")
    } finally {
        scheduledExecutor.shutdown()
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=1}
fun bad_case_14() {
    val executor = Executors.newSingleThreadExecutor()
    
    val future = CompletableFuture.supplyAsync({
        // Simulate a resource-intensive operation
        val result = calculatePrimes(1_000_000)
        "Found ${result.size} prime numbers"
    }, executor)
    
    try {
        // ruleid: kotlin-misconfigured-concurrency
        val result = future.get() // No timeout for potentially slow operation
        println(result)
    } catch (e: Exception) {
        println("Calculation error: ${e.message}")
    } finally {
        executor.shutdown()
    }
}
// {/fact}

fun calculatePrimes(max: Int): List<Int> {
    val primes = mutableListOf<Int>()
    for (i in 2..max) {
        var isPrime = true
        for (j in 2..Math.sqrt(i.toDouble()).toInt()) {
            if (i % j == 0) {
                isPrime = false
                break
            }
        }
        if (isPrime) primes.add(i)
    }
    return primes
}

// {fact rule=misconfigured-concurrency@v1.0 defects=1}
fun bad_case_15() {
    val executor = Executors.newWorkStealingPool()
    
    val futures = mutableListOf<Future<String>>()
    for (i in 1..5) {
        futures.add(executor.submit<String> {
            // Simulate tasks with varying completion times
            Thread.sleep((Math.random() * 10000).toLong())
            "Task $i result"
        })
    }
    
    try {
        for (future in futures) {
            // ruleid: kotlin-misconfigured-concurrency
            val result = future.get() // No timeout for any task
            println(result)
        }
    } catch (e: Exception) {
        println("Task error: ${e.message}")
    } finally {
        executor.shutdown()
    }
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=misconfigured-concurrency@v1.0 defects=0}
fun good_case_1() {
    val executor = Executors.newSingleThreadExecutor()
    val future = executor.submit<String> {
        Thread.sleep(5000)
        "Result after processing"
    }
    
    try {
        // ok: kotlin-misconfigured-concurrency
        val result = future.get(10, TimeUnit.SECONDS) // Timeout specified
        println("Result: $result")
    } catch (e: TimeoutException) {
        println("Operation timed out")
    } catch (e: Exception) {
        println("Error: ${e.message}")
    } finally {
        executor.shutdown()
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=0}
fun good_case_2() {
    val completableFuture = CompletableFuture.supplyAsync {
        // Simulate a long-running operation
        Thread.sleep(3000)
        "Operation completed"
    }
    
    try {
        // ok: kotlin-misconfigured-concurrency
        val result = completableFuture.get(5, TimeUnit.SECONDS) // Timeout specified
        println("Got result: $result")
    } catch (e: TimeoutException) {
        println("Operation timed out after 5 seconds")
    } catch (e: Exception) {
        println("Exception occurred: ${e.message}")
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=0}
fun good_case_3() {
    val executor = Executors.newFixedThreadPool(2)
    
    val task1 = executor.submit<Int> {
        // This task might take some time
        Thread.sleep(2000)
        42
    }
    
    try {
        // ok: kotlin-misconfigured-concurrency
        val result = task1.get(3, TimeUnit.SECONDS) // Reasonable timeout
        println("Task completed with result: $result")
    } catch (e: TimeoutException) {
        println("Task timed out")
    } catch (e: Exception) {
        println("Task failed: ${e.message}")
    } finally {
        executor.shutdown()
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=0}
fun good_case_4() {
    val cf1 = CompletableFuture.supplyAsync {
        // Simulate network call
        Thread.sleep(1000)
        "Data from service 1"
    }
    
    val cf2 = CompletableFuture.supplyAsync {
        // Simulate database query
        Thread.sleep(2000)
        "Data from service 2"
    }
    
    try {
        // ok: kotlin-misconfigured-concurrency
        val result1 = cf1.get(2, TimeUnit.SECONDS) // Timeout specified
        // ok: kotlin-misconfigured-concurrency
        val result2 = cf2.get(3, TimeUnit.SECONDS) // Timeout specified
        println("Combined results: $result1 and $result2")
    } catch (e: TimeoutException) {
        println("One of the operations timed out")
    } catch (e: Exception) {
        println("Error in processing: ${e.message}")
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=0}
fun good_case_5() {
    val executor = Executors.newCachedThreadPool()
    val callables = mutableListOf<Callable<String>>()
    
    for (i in 1..5) {
        callables.add(Callable {
            Thread.sleep(500 * i)
            "Result $i"
        })
    }
    
    val futures = executor.invokeAll(callables)
    
    try {
        for (future in futures) {
            // ok: kotlin-misconfigured-concurrency
            val result = future.get(10, TimeUnit.SECONDS) // Timeout for each future
            println("Got: $result")
        }
    } catch (e: TimeoutException) {
        println("A task timed out")
    } catch (e: Exception) {
        println("Error: ${e.message}")
    } finally {
        executor.shutdown()
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=0}
fun good_case_6() {
    // Using thenApply and thenAccept instead of get()
    val completableFuture = CompletableFuture.supplyAsync {
        Thread.sleep(2000)
        "Async operation result"
    }
    
    // ok: kotlin-misconfigured-concurrency
    completableFuture
        .thenApply { result -> "Processed: $result" }
        .thenAccept { processed -> println(processed) }
        .exceptionally { e ->
            println("Error: ${e.message}")
            null
        }
    
    // Allow some time for the async operations to complete
    Thread.sleep(3000)
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=0}
fun good_case_7() {
    val executor = Executors.newSingleThreadExecutor()
    
    val future = executor.submit<Int> {
        var sum = 0
        for (i in 1..1000) {
            sum += i
        }
        sum
    }
    
    try {
        println("Waiting for result...")
        // ok: kotlin-misconfigured-concurrency
        val result = future.get(5, TimeUnit.SECONDS) // Reasonable timeout
        println("Sum: $result")
    } catch (e: TimeoutException) {
        println("Calculation took too long")
    } catch (e: Exception) {
        println("Calculation error: ${e.message}")
    } finally {
        executor.shutdown()
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=0}
fun good_case_8() {
    // Using non-blocking CompletableFuture methods
    val future1 = CompletableFuture.supplyAsync {
        Thread.sleep(1000)
        "Result from first task"
    }
    
    val future2 = CompletableFuture.supplyAsync {
        Thread.sleep(2000)
        "Result from second task"
    }
    
    // ok: kotlin-misconfigured-concurrency
    val combinedFuture = future1.thenCombine(future2) { result1, result2 ->
        "$result1 + $result2"
    }
    
    combinedFuture.thenAccept { result ->
        println("Combined result: $result")
    }
    
    // Wait a bit for demonstration purposes
    Thread.sleep(3000)
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=0}
fun good_case_9() {
    runBlocking {
        // Using Kotlin coroutines instead of CompletableFuture.get()
        val result = withTimeoutOrNull(5000) {
            // Simulating a long operation
            delay(3000)
            "Operation completed"
        }
        
        if (result != null) {
            println("Got result: $result")
        } else {
            println("Operation timed out")
        }
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=0}
fun good_case_10() {
    val executor = Executors.newSingleThreadExecutor()
    
    val future = executor.submit<String> {
        // Simulate a network operation
        Thread.sleep(2000)
        "Network response"
    }
    
    // ok: kotlin-misconfigured-concurrency
    // Using isDone() to check completion status without blocking
    var isDone = false
    var attempts = 0
    while (!isDone && attempts < 10) {
        isDone = future.isDone
        if (isDone) {
            try {
                val result = future.get(0, TimeUnit.MILLISECONDS) // Non-blocking get
                println("Result: $result")
            } catch (e: Exception) {
                println("Error: ${e.message}")
            }
        } else {
            println("Task not yet complete, waiting...")
            Thread.sleep(500)
            attempts++
        }
    }
    
    if (!isDone) {
        println("Giving up after multiple attempts")
        future.cancel(true)
    }
    
    executor.shutdown()
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=0}
fun good_case_11() {
    val executor = Executors.newFixedThreadPool(4)
    val completionService = ExecutorCompletionService<String>(executor)
    
    for (i in 1..5) {
        completionService.submit {
            Thread.sleep(500 * i)
            "Task $i completed"
        }
    }
    
    try {
        for (i in 1..5) {
            val future = completionService.take() // This is ok as it doesn't block indefinitely
            // ok: kotlin-misconfigured-concurrency
            val result = future.get(1, TimeUnit.SECONDS) // Timeout specified
            println(result)
        }
    } catch (e: TimeoutException) {
        println("A task took too long")
    } catch (e: Exception) {
        println("Error: ${e.message}")
    } finally {
        executor.shutdown()
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=0}
fun good_case_12() {
    // Using CompletableFuture.orTimeout instead of get with timeout
    val future = CompletableFuture.supplyAsync {
        Thread.sleep(2000)
        "Task completed"
    }
    
    // ok: kotlin-misconfigured-concurrency
    future
        .orTimeout(3, TimeUnit.SECONDS)
        .whenComplete { result, exception ->
            if (exception != null) {
                if (exception is TimeoutException) {
                    println("Task timed out")
                } else {
                    println("Task failed: ${exception.message}")
                }
            } else {
                println("Result: $result")
            }
        }
    
    // Wait for completion
    Thread.sleep(4000)
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=0}
fun good_case_13() {
    val scheduledExecutor = Executors.newScheduledThreadPool(1)
    
    val future = scheduledExecutor.schedule({
        Thread.sleep(2000)
        "Scheduled task completed"
    }, 1, TimeUnit.SECONDS)
    
    try {
        println("Waiting for scheduled task...")
        // ok: kotlin-misconfigured-concurrency
        val result = future.get(5, TimeUnit.SECONDS) // Timeout specified
        println(result)
    } catch (e: TimeoutException) {
        println("Scheduled task timed out")
    } catch (e: Exception) {
        println("Scheduled task error: ${e.message}")
    } finally {
        scheduledExecutor.shutdown()
    }
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=0}
fun good_case_14() {
    // Using CompletableFuture.getNow instead of get
    val future = CompletableFuture.supplyAsync {
        try {
            Thread.sleep(3000)
            "Task result"
        } catch (e: InterruptedException) {
            "Interrupted"
        }
    }
    
    // ok: kotlin-misconfigured-concurrency
    val result = future.getNow("Default value if not done") // Non-blocking alternative
    println("Immediate result (may be default): $result")
    
    // Wait a bit and check again
    Thread.sleep(4000)
    val finalResult = future.getNow("Default value if not done")
    println("Final result: $finalResult")
}
// {/fact}

// {fact rule=misconfigured-concurrency@v1.0 defects=0}
fun good_case_15() {
    // Using CompletableFuture.completeOnTimeout
    val future = CompletableFuture<String>()
    
    thread {
        try {
            Thread.sleep(4000) // Simulate long operation
            future.complete("Actual result")
        } catch (e: InterruptedException) {
            future.completeExceptionally(e)
        }
    }
    
    // ok: kotlin-misconfigured-concurrency
    future
        .completeOnTimeout("Fallback result", 2, TimeUnit.SECONDS)
        .thenAccept { result ->
            println("Result (possibly fallback): $result")
        }
    
    // Wait for demonstration
    Thread.sleep(5000)
}
// {/fact}