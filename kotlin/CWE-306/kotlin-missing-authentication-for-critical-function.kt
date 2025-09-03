// Import necessary libraries for Spring Security and web functionality
import org.springframework.web.bind.annotation.*
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.access.annotation.Secured
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Controller
import org.springframework.stereotype.Service
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.http.HttpStatus
import java.util.*

// TRUE POSITIVES (Vulnerable Code Examples)

// Example 1: Admin endpoint without authentication
@RestController
@RequestMapping("/api/admin")
class bad_case_1 {
    
    // ruleid: kotlin-missing-authentication-for-critical-function
    @GetMapping("/users")
    fun getAllUsers(): ResponseEntity<List<String>> {
        // Critical function to get all users without authentication
        val users = listOf("user1", "user2", "admin")
        return ResponseEntity.ok(users)
    }
}

// Example 2: Delete user endpoint without authentication
@RestController
@RequestMapping("/api")
class bad_case_2 {
    
    // ruleid: kotlin-missing-authentication-for-critical-function
    @DeleteMapping("/users/{id}")
    fun deleteUser(@PathVariable id: Long): ResponseEntity<String> {
        // Critical function to delete a user without authentication
        return ResponseEntity.ok("User $id deleted successfully")
    }
}

// Example 3: Update user permissions without authentication
@RestController
class bad_case_3 {
    
    // ruleid: kotlin-missing-authentication-for-critical-function
    @PutMapping("/permissions/{userId}")
    fun updatePermissions(@PathVariable userId: Long, @RequestBody permissions: Map<String, Boolean>): ResponseEntity<String> {
        // Critical function to update user permissions without authentication
        return ResponseEntity.ok("Permissions updated for user $userId")
    }
}

// Example 4: Reset password endpoint without authentication
@RestController
class bad_case_4 {
    
    // ruleid: kotlin-missing-authentication-for-critical-function
    @PostMapping("/reset-password")
    fun resetPassword(@RequestParam email: String): ResponseEntity<String> {
        // Critical function to reset password without authentication
        return ResponseEntity.ok("Password reset email sent to $email")
    }
}

// Example 5: Access sensitive data without authentication
@RestController
class bad_case_5 {
    
    // ruleid: kotlin-missing-authentication-for-critical-function
    @GetMapping("/financial-reports")
    fun getFinancialReports(): ResponseEntity<List<String>> {
        // Critical function to access financial reports without authentication
        val reports = listOf("Q1 Report", "Q2 Report", "Annual Report")
        return ResponseEntity.ok(reports)
    }
}

// Example 6: Service with critical method lacking authentication
@Service
class bad_case_6 {
    
    // ruleid: kotlin-missing-authentication-for-critical-function
    fun transferFunds(fromAccount: String, toAccount: String, amount: Double): Boolean {
        // Critical function to transfer funds without authentication
        println("Transferring $amount from $fromAccount to $toAccount")
        return true
    }
}

// Example 7: API endpoint exposing sensitive user data
@RestController
class bad_case_7 {
    
    // ruleid: kotlin-missing-authentication-for-critical-function
    @GetMapping("/users/{id}/personal-data")
    fun getUserPersonalData(@PathVariable id: Long): ResponseEntity<Map<String, String>> {
        // Critical function exposing personal data without authentication
        val personalData = mapOf(
            "ssn" to "123-45-6789",
            "dob" to "1980-01-01",
            "address" to "123 Main St"
        )
        return ResponseEntity.ok(personalData)
    }
}

// Example 8: System configuration endpoint without authentication
@RestController
class bad_case_8 {
    
    // ruleid: kotlin-missing-authentication-for-critical-function
    @PutMapping("/system/config")
    fun updateSystemConfig(@RequestBody config: Map<String, String>): ResponseEntity<String> {
        // Critical function to update system configuration without authentication
        return ResponseEntity.ok("System configuration updated")
    }
}

// Example 9: Database backup endpoint without authentication
@RestController
class bad_case_9 {
    
    // ruleid: kotlin-missing-authentication-for-critical-function
    @PostMapping("/database/backup")
    fun backupDatabase(): ResponseEntity<String> {
        // Critical function to backup database without authentication
        return ResponseEntity.ok("Database backup initiated")
    }
}

// Example 10: User registration approval without authentication
@RestController
class bad_case_10 {
    
    // ruleid: kotlin-missing-authentication-for-critical-function
    @PostMapping("/users/approve/{id}")
    fun approveUserRegistration(@PathVariable id: Long): ResponseEntity<String> {
        // Critical function to approve user registration without authentication
        return ResponseEntity.ok("User $id approved")
    }
}

// Example 11: Payment processing without authentication
@RestController
class bad_case_11 {
    
    // ruleid: kotlin-missing-authentication-for-critical-function
    @PostMapping("/payments/process")
    fun processPayment(@RequestBody paymentDetails: Map<String, String>): ResponseEntity<String> {
        // Critical function to process payments without authentication
        val amount = paymentDetails["amount"] ?: "0"
        return ResponseEntity.ok("Payment of $$amount processed")
    }
}

// Example 12: API key generation without authentication
@RestController
class bad_case_12 {
    
    // ruleid: kotlin-missing-authentication-for-critical-function
    @PostMapping("/api-keys/generate")
    fun generateApiKey(@RequestParam userId: Long): ResponseEntity<String> {
        // Critical function to generate API keys without authentication
        val apiKey = UUID.randomUUID().toString()
        return ResponseEntity.ok("API key for user $userId: $apiKey")
    }
}

// Example 13: Server shutdown endpoint without authentication
@RestController
class bad_case_13 {
    
    // ruleid: kotlin-missing-authentication-for-critical-function
    @PostMapping("/server/shutdown")
    fun shutdownServer(): ResponseEntity<String> {
        // Critical function to shutdown server without authentication
        return ResponseEntity.ok("Server shutdown initiated")
    }
}

// Example 14: Log access without authentication
@RestController
class bad_case_14 {
    
    // ruleid: kotlin-missing-authentication-for-critical-function
    @GetMapping("/logs")
    fun getSystemLogs(): ResponseEntity<List<String>> {
        // Critical function to access system logs without authentication
        val logs = listOf("Log entry 1", "Log entry 2", "Log entry 3")
        return ResponseEntity.ok(logs)
    }
}

// Example 15: User impersonation without authentication
@RestController
class bad_case_15 {
    
    // ruleid: kotlin-missing-authentication-for-critical-function
    @PostMapping("/impersonate/{userId}")
    fun impersonateUser(@PathVariable userId: Long): ResponseEntity<String> {
        // Critical function to impersonate users without authentication
        return ResponseEntity.ok("Now impersonating user $userId")
    }
}

// TRUE NEGATIVES (Secure Code Examples)

// Example 1: Admin endpoint with proper authentication
@RestController
@RequestMapping("/api/admin")
class good_case_1 {
    
    // ok: kotlin-missing-authentication-for-critical-function
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    fun getAllUsers(): ResponseEntity<List<String>> {
        // Critical function protected with PreAuthorize annotation
        val users = listOf("user1", "user2", "admin")
        return ResponseEntity.ok(users)
    }
}

// Example 2: Delete user endpoint with proper authentication
@RestController
@RequestMapping("/api")
class good_case_2 {
    
    // ok: kotlin-missing-authentication-for-critical-function
    @Secured("ROLE_ADMIN")
    @DeleteMapping("/users/{id}")
    fun deleteUser(@PathVariable id: Long): ResponseEntity<String> {
        // Critical function protected with Secured annotation
        return ResponseEntity.ok("User $id deleted successfully")
    }
}

// Example 3: Update user permissions with proper authentication
@RestController
class good_case_3 {
    
    // ok: kotlin-missing-authentication-for-critical-function
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.id")
    @PutMapping("/permissions/{userId}")
    fun updatePermissions(@PathVariable userId: Long, @RequestBody permissions: Map<String, Boolean>): ResponseEntity<String> {
        // Critical function protected with PreAuthorize annotation with SpEL expression
        return ResponseEntity.ok("Permissions updated for user $userId")
    }
}

// Example 4: Reset password endpoint with proper authentication
@RestController
class good_case_4 {
    
    // ok: kotlin-missing-authentication-for-critical-function
    @PreAuthorize("isAuthenticated()")
    @PostMapping("/reset-password")
    fun resetPassword(@RequestParam email: String): ResponseEntity<String> {
        // Critical function protected with PreAuthorize annotation
        return ResponseEntity.ok("Password reset email sent to $email")
    }
}

// Example 5: Access sensitive data with proper authentication
@RestController
class good_case_5 {
    
    // ok: kotlin-missing-authentication-for-critical-function
    @PreAuthorize("hasAnyRole('ADMIN', 'FINANCE')")
    @GetMapping("/financial-reports")
    fun getFinancialReports(): ResponseEntity<List<String>> {
        // Critical function protected with PreAuthorize annotation
        val reports = listOf("Q1 Report", "Q2 Report", "Annual Report")
        return ResponseEntity.ok(reports)
    }
}

// Example 6: Service with critical method having authentication check
@Service
class good_case_6 {
    
    // ok: kotlin-missing-authentication-for-critical-function
    @PreAuthorize("hasRole('FINANCE')")
    fun transferFunds(fromAccount: String, toAccount: String, amount: Double): Boolean {
        // Critical function protected with PreAuthorize annotation
        println("Transferring $amount from $fromAccount to $toAccount")
        return true
    }
}

// Example 7: API endpoint with proper authentication for sensitive data
@RestController
class good_case_7 {
    
    // ok: kotlin-missing-authentication-for-critical-function
    @PreAuthorize("#id == authentication.principal.id or hasRole('ADMIN')")
    @GetMapping("/users/{id}/personal-data")
    fun getUserPersonalData(@PathVariable id: Long): ResponseEntity<Map<String, String>> {
        // Critical function protected with PreAuthorize annotation with SpEL expression
        val personalData = mapOf(
            "ssn" to "123-45-6789",
            "dob" to "1980-01-01",
            "address" to "123 Main St"
        )
        return ResponseEntity.ok(personalData)
    }
}

// Example 8: System configuration endpoint with proper authentication
@RestController
class good_case_8 {
    
    // ok: kotlin-missing-authentication-for-critical-function
    @Secured("ROLE_SYSTEM_ADMIN")
    @PutMapping("/system/config")
    fun updateSystemConfig(@RequestBody config: Map<String, String>): ResponseEntity<String> {
        // Critical function protected with Secured annotation
        return ResponseEntity.ok("System configuration updated")
    }
}

// Example 9: Database backup endpoint with proper authentication
@RestController
class good_case_9 {
    
    // ok: kotlin-missing-authentication-for-critical-function
    @PreAuthorize("hasRole('DB_ADMIN')")
    @PostMapping("/database/backup")
    fun backupDatabase(): ResponseEntity<String> {
        // Critical function protected with PreAuthorize annotation
        return ResponseEntity.ok("Database backup initiated")
    }
}

// Example 10: User registration approval with proper authentication
@RestController
class good_case_10 {
    
    // ok: kotlin-missing-authentication-for-critical-function
    @Secured({"ROLE_ADMIN", "ROLE_USER_MANAGER"})
    @PostMapping("/users/approve/{id}")
    fun approveUserRegistration(@PathVariable id: Long): ResponseEntity<String> {
        // Critical function protected with Secured annotation
        return ResponseEntity.ok("User $id approved")
    }
}

// Example 11: Payment processing with proper authentication
@RestController
class good_case_11 {
    
    // ok: kotlin-missing-authentication-for-critical-function
    @PreAuthorize("hasRole('PAYMENT_PROCESSOR') and hasAuthority('PROCESS_PAYMENT')")
    @PostMapping("/payments/process")
    fun processPayment(@RequestBody paymentDetails: Map<String, String>): ResponseEntity<String> {
        // Critical function protected with PreAuthorize annotation with multiple conditions
        val amount = paymentDetails["amount"] ?: "0"
        return ResponseEntity.ok("Payment of $$amount processed")
    }
}

// Example 12: API key generation with proper authentication
@RestController
class good_case_12 {
    
    // ok: kotlin-missing-authentication-for-critical-function
    @PreAuthorize("hasRole('ADMIN') or (hasRole('USER') and #userId == authentication.principal.id)")
    @PostMapping("/api-keys/generate")
    fun generateApiKey(@RequestParam userId: Long): ResponseEntity<String> {
        // Critical function protected with PreAuthorize annotation with complex SpEL expression
        val apiKey = UUID.randomUUID().toString()
        return ResponseEntity.ok("API key for user $userId: $apiKey")
    }
}

// Example 13: Server shutdown endpoint with proper authentication
@RestController
class good_case_13 {
    
    // ok: kotlin-missing-authentication-for-critical-function
    @Secured("ROLE_SYSTEM_ADMIN")
    @PostMapping("/server/shutdown")
    fun shutdownServer(): ResponseEntity<String> {
        // Critical function protected with Secured annotation
        return ResponseEntity.ok("Server shutdown initiated")
    }
}

// Example 14: Log access with proper authentication
@RestController
class good_case_14 {
    
    // ok: kotlin-missing-authentication-for-critical-function
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_AUDITOR')")
    @GetMapping("/logs")
    fun getSystemLogs(): ResponseEntity<List<String>> {
        // Critical function protected with PreAuthorize annotation
        val logs = listOf("Log entry 1", "Log entry 2", "Log entry 3")
        return ResponseEntity.ok(logs)
    }
}

// Example 15: User impersonation with proper authentication
@RestController
class good_case_15 {
    
    // ok: kotlin-missing-authentication-for-critical-function
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('USER_IMPERSONATION')")
    @PostMapping("/impersonate/{userId}")
    fun impersonateUser(@PathVariable userId: Long): ResponseEntity<String> {
        // Critical function protected with PreAuthorize annotation with multiple conditions
        return ResponseEntity.ok("Now impersonating user $userId")
    }
}