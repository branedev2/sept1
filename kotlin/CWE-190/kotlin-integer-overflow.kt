// Integer Overflow Examples in Kotlin

// True Positives (Vulnerable Code)

// {fact rule=arithmetic-overflow@v1.0 defects=1}
fun bad_case_1() {
    val maxInt = Int.MAX_VALUE
    // ruleid: kotlin-integer-overflow
    val result = maxInt + 1 // Integer overflow occurs here
    println("Result: $result") // Will print a negative number due to overflow
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
fun bad_case_2() {
    val a = 2000000000
    val b = 1000000000
    // ruleid: kotlin-integer-overflow
    val product = a * b // Integer overflow occurs here
    println("Product: $product") // Will print an incorrect result due to overflow
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
fun bad_case_3() {
    val userInput = "2147483647" // Max int value
    val value = userInput.toInt()
    // ruleid: kotlin-integer-overflow
    val incremented = value + 1 // Integer overflow occurs here
    println("Incremented value: $incremented") // Will print -2147483648
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
fun bad_case_4() {
    val count = Int.MAX_VALUE
    // ruleid: kotlin-integer-overflow
    val newCount = count + 10 // Integer overflow occurs here
    println("New count: $newCount") // Will print a negative number
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
fun bad_case_5() {
    val values = listOf(1000000000, 1000000000, 1000000000)
    var sum = 0
    for (value in values) {
        // ruleid: kotlin-integer-overflow
        sum += value // Integer overflow occurs during addition
    }
    println("Sum: $sum") // Will print an incorrect sum due to overflow
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
fun bad_case_6() {
    val base = 1000
    var result = 1
    for (i in 1..32) {
        // ruleid: kotlin-integer-overflow
        result *= base // Integer overflow occurs during multiplication
    }
    println("Result: $result") // Will print an incorrect result due to overflow
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
fun bad_case_7() {
    val maxByte = Byte.MAX_VALUE.toInt()
    // ruleid: kotlin-integer-overflow
    val nextByte = (maxByte + 1).toByte() // Integer overflow when converting back to byte
    println("Next byte: $nextByte") // Will print -128 instead of 128
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
fun bad_case_8() {
    val a = 100000
    val b = 100000
    // ruleid: kotlin-integer-overflow
    val squared = a * b * b // Integer overflow during multiplication
    println("Squared: $squared") // Will print an incorrect result
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
fun bad_case_9() {
    val startValue = Int.MAX_VALUE - 5
    var counter = startValue
    for (i in 1..10) {
        // ruleid: kotlin-integer-overflow
        counter += 1 // Integer overflow after a few iterations
        println("Counter: $counter")
    }
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
fun bad_case_10() {
    val factorial = calculateLargeFactorial(20) // 20! is much larger than Int.MAX_VALUE
    println("Factorial: $factorial") // Will print an incorrect result due to overflow
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
fun calculateLargeFactorial(n: Int): Int {
    var result = 1
    for (i in 2..n) {
        // ruleid: kotlin-integer-overflow
        result *= i // Integer overflow occurs during multiplication
    }
    return result
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
fun bad_case_11() {
    val seconds = 60
    val minutes = 60
    val hours = 24
    val days = 365
    val years = 100
    // ruleid: kotlin-integer-overflow
    val totalSeconds = seconds * minutes * hours * days * years // Integer overflow
    println("Total seconds in a century: $totalSeconds") // Incorrect result
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
fun bad_case_12() {
    val population = 8000000000L // World population (exceeds Int.MAX_VALUE)
    // ruleid: kotlin-integer-overflow
    val populationInt = population.toInt() // Overflow when converting Long to Int
    println("Population: $populationInt") // Will print a negative number
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
fun bad_case_13() {
    val maxShort = Short.MAX_VALUE.toInt()
    // ruleid: kotlin-integer-overflow
    val result = maxShort + 1000 // No overflow in Int
    // ruleid: kotlin-integer-overflow
    val backToShort = result.toShort() // Overflow when converting back to Short
    println("Result as short: $backToShort") // Will print a negative number
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
fun bad_case_14() {
    val itemPrice = 100
    val quantity = Int.MAX_VALUE / 50
    // ruleid: kotlin-integer-overflow
    val totalCost = itemPrice * quantity // Integer overflow
    println("Total cost: $totalCost") // Will print an incorrect total
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
fun bad_case_15() {
    val array = IntArray(10) { it * 1000000000 }
    var product = 1
    for (value in array) {
        if (value != 0) {
            // ruleid: kotlin-integer-overflow
            product *= value // Integer overflow during multiplication
        }
    }
    println("Product: $product") // Will print an incorrect product
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=arithmetic-overflow@v1.0 defects=0}
fun good_case_1() {
    val maxInt = Int.MAX_VALUE
    // ok: kotlin-integer-overflow
    val result = maxInt.toLong() + 1 // Using Long to prevent overflow
    println("Result: $result") // Will print correct value 2147483648
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
fun good_case_2() {
    val a = 2000000000L
    val b = 1000000000L
    // ok: kotlin-integer-overflow
    val product = a * b // Using Long to prevent overflow
    println("Product: $product") // Will print correct result
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
fun good_case_3() {
    val userInput = "2147483647" // Max int value
    val value = userInput.toLong() // Convert to Long instead of Int
    // ok: kotlin-integer-overflow
    val incremented = value + 1 // No overflow with Long
    println("Incremented value: $incremented") // Will print 2147483648
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
fun good_case_4() {
    val count = Int.MAX_VALUE
    // ok: kotlin-integer-overflow
    val newCount = count.toLong() + 10 // Using Long to prevent overflow
    println("New count: $newCount") // Will print correct value
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
fun good_case_5() {
    val values = listOf(1000000000, 1000000000, 1000000000)
    var sum = 0L // Using Long for the sum
    for (value in values) {
        // ok: kotlin-integer-overflow
        sum += value // No overflow with Long
    }
    println("Sum: $sum") // Will print correct sum
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
fun good_case_6() {
    val base = 1000L
    var result = 1L
    for (i in 1..32) {
        // ok: kotlin-integer-overflow
        result *= base // No overflow with Long
    }
    println("Result: $result") // Will print correct result
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
fun good_case_7() {
    val maxByte = Byte.MAX_VALUE.toInt()
    // ok: kotlin-integer-overflow
    if (maxByte + 1 <= 255) { // Check before conversion
        val nextByte = (maxByte + 1).toByte()
        println("Next byte: $nextByte")
    } else {
        println("Value would overflow byte range")
    }
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
fun good_case_8() {
    val a = 100000L
    val b = 100000L
    // ok: kotlin-integer-overflow
    val squared = a * b * b // Using Long to prevent overflow
    println("Squared: $squared") // Will print correct result
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
fun good_case_9() {
    val startValue = Int.MAX_VALUE - 5
    var counter = startValue.toLong() // Using Long instead of Int
    for (i in 1..10) {
        // ok: kotlin-integer-overflow
        counter += 1 // No overflow with Long
        println("Counter: $counter")
    }
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
fun good_case_10() {
    val factorial = calculateLargeFactorialSafely(20) // Using BigInteger for large factorial
    println("Factorial: $factorial") // Will print correct result
}
// {/fact}

import java.math.BigInteger

// {fact rule=arithmetic-overflow@v1.0 defects=0}
fun calculateLargeFactorialSafely(n: Int): BigInteger {
    var result = BigInteger.ONE
    for (i in 2..n) {
        // ok: kotlin-integer-overflow
        result = result.multiply(BigInteger.valueOf(i.toLong())) // Using BigInteger to prevent overflow
    }
    return result
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
fun good_case_11() {
    val seconds = 60L
    val minutes = 60L
    val hours = 24L
    val days = 365L
    val years = 100L
    // ok: kotlin-integer-overflow
    val totalSeconds = seconds * minutes * hours * days * years // Using Long to prevent overflow
    println("Total seconds in a century: $totalSeconds") // Correct result
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
fun good_case_12() {
    val population = 8000000000L // World population
    // ok: kotlin-integer-overflow
    println("Population: $population") // Use Long directly instead of converting to Int
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
fun good_case_13() {
    val maxShort = Short.MAX_VALUE.toInt()
    val result = maxShort + 1000 // No overflow in Int
    // ok: kotlin-integer-overflow
    if (result <= Short.MAX_VALUE) {
        val backToShort = result.toShort()
        println("Result as short: $backToShort")
    } else {
        println("Value $result is too large for Short type")
    }
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
fun good_case_14() {
    val itemPrice = 100L
    val quantity = Int.MAX_VALUE / 50
    // ok: kotlin-integer-overflow
    val totalCost = itemPrice * quantity // Using Long to prevent overflow
    println("Total cost: $totalCost") // Will print correct total
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
fun good_case_15() {
    val array = IntArray(10) { it * 1000000000 }
    var product = BigInteger.ONE
    for (value in array) {
        if (value != 0) {
            // ok: kotlin-integer-overflow
            product = product.multiply(BigInteger.valueOf(value.toLong())) // Using BigInteger to prevent overflow
        }
    }
    println("Product: $product") // Will print correct product
}
// {/fact}