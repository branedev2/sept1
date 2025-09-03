import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder
import org.springframework.security.crypto.password.StandardPasswordEncoder
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.core.userdetails.User

// True Positives (Vulnerable Code)

// {fact rule=weak-password-encoding@v1.0 defects=1}
fun bad_case_1() {
    // ruleid: kotlin-weak-password-encoder
    val passwordEncoder: PasswordEncoder = NoOpPasswordEncoder.getInstance()
    
    val authProvider = DaoAuthenticationProvider()
    authProvider.setPasswordEncoder(passwordEncoder)
    authProvider.setUserDetailsService(createUserDetailsService())
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=1}
fun bad_case_2() {
    // ruleid: kotlin-weak-password-encoder
    val passwordEncoder: PasswordEncoder = StandardPasswordEncoder()
    
    val userService = UserService()
    userService.setPasswordEncoder(passwordEncoder)
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=1}
fun bad_case_3() {
    // ruleid: kotlin-weak-password-encoder
    val passwordEncoder = MessageDigestPasswordEncoder("SHA-256")
    
    val user = User.builder()
        .username("admin")
        .password(passwordEncoder.encode("password"))
        .roles("ADMIN")
        .build()
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=1}
fun bad_case_4() {
    class SecurityConfig : WebSecurityConfigurerAdapter() {
        override fun configure(auth: AuthenticationManagerBuilder) {
            // ruleid: kotlin-weak-password-encoder
            auth.inMemoryAuthentication()
                .passwordEncoder(NoOpPasswordEncoder.getInstance())
                .withUser("user")
                .password("password")
                .roles("USER")
        }
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=1}
fun bad_case_5() {
    @Configuration
    class SecurityConfiguration {
        @Bean
        fun passwordEncoder(): PasswordEncoder {
            // ruleid: kotlin-weak-password-encoder
            return MessageDigestPasswordEncoder("MD5")
        }
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=1}
fun bad_case_6() {
    class UserService {
        private lateinit var passwordEncoder: PasswordEncoder
        
        fun init() {
            // ruleid: kotlin-weak-password-encoder
            passwordEncoder = StandardPasswordEncoder("secret")
        }
        
        fun createUser(username: String, password: String) {
            val encodedPassword = passwordEncoder.encode(password)
            // Save user with encoded password
        }
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=1}
fun bad_case_7() {
    // ruleid: kotlin-weak-password-encoder
    val passwordEncoder = MessageDigestPasswordEncoder("SHA-1")
    
    class AuthService(private val passwordEncoder: PasswordEncoder) {
        fun authenticate(username: String, password: String): Boolean {
            val storedPassword = getStoredPassword(username)
            return passwordEncoder.matches(password, storedPassword)
        }
        
        private fun getStoredPassword(username: String): String {
            // Get stored password from database
            return "encodedPassword"
        }
    }
    
    val authService = AuthService(passwordEncoder)
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=1}
fun bad_case_8() {
    class PasswordService {
        fun encodePassword(rawPassword: String): String {
            // ruleid: kotlin-weak-password-encoder
            val encoder = NoOpPasswordEncoder.getInstance()
            return encoder.encode(rawPassword)
        }
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=1}
fun bad_case_9() {
    @Configuration
    class WebSecurityConfig : WebSecurityConfigurerAdapter() {
        @Bean
        fun userDetailsService(): UserDetailsService {
            // ruleid: kotlin-weak-password-encoder
            val encoder = MessageDigestPasswordEncoder("SHA-256")
            
            val manager = InMemoryUserDetailsManager()
            val user = User.withUsername("user")
                .password(encoder.encode("password"))
                .roles("USER")
                .build()
            manager.createUser(user)
            return manager
        }
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=1}
fun bad_case_10() {
    class CustomAuthenticationProvider {
        private val userRepository = UserRepository()
        
        fun authenticate(username: String, password: String): Boolean {
            val user = userRepository.findByUsername(username)
            if (user != null) {
                // ruleid: kotlin-weak-password-encoder
                val encoder = StandardPasswordEncoder()
                return encoder.matches(password, user.password)
            }
            return false
        }
    }
    
    class UserRepository {
        fun findByUsername(username: String): User? {
            // Find user in database
            return User("username", "encodedPassword", listOf())
        }
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=1}
fun bad_case_11() {
    class PasswordResetService {
        fun resetPassword(username: String, newPassword: String) {
            // ruleid: kotlin-weak-password-encoder
            val encoder = MessageDigestPasswordEncoder("MD5")
            val encodedPassword = encoder.encode(newPassword)
            
            // Update password in database
            updateUserPassword(username, encodedPassword)
        }
        
        private fun updateUserPassword(username: String, encodedPassword: String) {
            // Update password in database
        }
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=1}
fun bad_case_12() {
    @Configuration
    class SecurityConfig {
        @Bean
        fun authenticationProvider(): DaoAuthenticationProvider {
            val provider = DaoAuthenticationProvider()
            provider.setUserDetailsService(userDetailsService())
            // ruleid: kotlin-weak-password-encoder
            provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance())
            return provider
        }
        
        @Bean
        fun userDetailsService(): UserDetailsService {
            // Return user details service
            return InMemoryUserDetailsManager()
        }
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=1}
fun bad_case_13() {
    class UserRegistrationService {
        fun registerUser(username: String, password: String) {
            // ruleid: kotlin-weak-password-encoder
            val encoder = MessageDigestPasswordEncoder("SHA-1")
            val encodedPassword = encoder.encode(password)
            
            val user = User(username, encodedPassword, emptyList())
            saveUser(user)
        }
        
        private fun saveUser(user: User) {
            // Save user to database
        }
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=1}
fun bad_case_14() {
    class LegacyPasswordMigrationService {
        fun migratePasswords() {
            val users = getAllUsers()
            
            // ruleid: kotlin-weak-password-encoder
            val oldEncoder = StandardPasswordEncoder()
            
            for (user in users) {
                // Migrate passwords using weak encoder
                val decodedPassword = decodePassword(user.password)
                val reEncodedPassword = oldEncoder.encode(decodedPassword)
                updateUserPassword(user.id, reEncodedPassword)
            }
        }
        
        private fun getAllUsers(): List<User> = listOf()
        private fun decodePassword(password: String): String = ""
        private fun updateUserPassword(id: Int, password: String) {}
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=1}
fun bad_case_15() {
    class CustomSecurityConfig {
        fun configureGlobal(auth: AuthenticationManagerBuilder) {
            // ruleid: kotlin-weak-password-encoder
            val encoder = MessageDigestPasswordEncoder("SHA-256")
            
            auth.inMemoryAuthentication()
                .withUser("admin")
                .password(encoder.encode("adminPass"))
                .roles("ADMIN")
                .and()
                .withUser("user")
                .password(encoder.encode("userPass"))
                .roles("USER")
        }
    }
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=weak-password-encoding@v1.0 defects=0}
fun good_case_1() {
    // ok: kotlin-weak-password-encoder
    val passwordEncoder = BCryptPasswordEncoder()
    
    val authProvider = DaoAuthenticationProvider()
    authProvider.setPasswordEncoder(passwordEncoder)
    authProvider.setUserDetailsService(createUserDetailsService())
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=0}
fun good_case_2() {
    // ok: kotlin-weak-password-encoder
    val passwordEncoder = Pbkdf2PasswordEncoder()
    
    val userService = UserService()
    userService.setPasswordEncoder(passwordEncoder)
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=0}
fun good_case_3() {
    // ok: kotlin-weak-password-encoder
    val passwordEncoder = Argon2PasswordEncoder()
    
    val user = User.builder()
        .username("admin")
        .password(passwordEncoder.encode("password"))
        .roles("ADMIN")
        .build()
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=0}
fun good_case_4() {
    class SecurityConfig : WebSecurityConfigurerAdapter() {
        override fun configure(auth: AuthenticationManagerBuilder) {
            // ok: kotlin-weak-password-encoder
            auth.inMemoryAuthentication()
                .passwordEncoder(BCryptPasswordEncoder())
                .withUser("user")
                .password("password")
                .roles("USER")
        }
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=0}
fun good_case_5() {
    @Configuration
    class SecurityConfiguration {
        @Bean
        fun passwordEncoder(): PasswordEncoder {
            // ok: kotlin-weak-password-encoder
            return SCryptPasswordEncoder()
        }
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=0}
fun good_case_6() {
    class UserService {
        private lateinit var passwordEncoder: PasswordEncoder
        
        fun init() {
            // ok: kotlin-weak-password-encoder
            passwordEncoder = BCryptPasswordEncoder(12)
        }
        
        fun createUser(username: String, password: String) {
            val encodedPassword = passwordEncoder.encode(password)
            // Save user with encoded password
        }
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=0}
fun good_case_7() {
    // ok: kotlin-weak-password-encoder
    val passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()
    
    class AuthService(private val passwordEncoder: PasswordEncoder) {
        fun authenticate(username: String, password: String): Boolean {
            val storedPassword = getStoredPassword(username)
            return passwordEncoder.matches(password, storedPassword)
        }
        
        private fun getStoredPassword(username: String): String {
            // Get stored password from database
            return "encodedPassword"
        }
    }
    
    val authService = AuthService(passwordEncoder)
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=0}
fun good_case_8() {
    class PasswordService {
        fun encodePassword(rawPassword: String): String {
            // ok: kotlin-weak-password-encoder
            val encoder = Pbkdf2PasswordEncoder("secret", 16, 310000, 32)
            return encoder.encode(rawPassword)
        }
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=0}
fun good_case_9() {
    @Configuration
    class WebSecurityConfig : WebSecurityConfigurerAdapter() {
        @Bean
        fun userDetailsService(): UserDetailsService {
            // ok: kotlin-weak-password-encoder
            val encoder = BCryptPasswordEncoder()
            
            val manager = InMemoryUserDetailsManager()
            val user = User.withUsername("user")
                .password(encoder.encode("password"))
                .roles("USER")
                .build()
            manager.createUser(user)
            return manager
        }
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=0}
fun good_case_10() {
    class CustomAuthenticationProvider {
        private val userRepository = UserRepository()
        
        fun authenticate(username: String, password: String): Boolean {
            val user = userRepository.findByUsername(username)
            if (user != null) {
                // ok: kotlin-weak-password-encoder
                val encoder = Argon2PasswordEncoder()
                return encoder.matches(password, user.password)
            }
            return false
        }
    }
    
    class UserRepository {
        fun findByUsername(username: String): User? {
            // Find user in database
            return User("username", "encodedPassword", listOf())
        }
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=0}
fun good_case_11() {
    class PasswordResetService {
        fun resetPassword(username: String, newPassword: String) {
            // ok: kotlin-weak-password-encoder
            val encoder = BCryptPasswordEncoder(12)
            val encodedPassword = encoder.encode(newPassword)
            
            // Update password in database
            updateUserPassword(username, encodedPassword)
        }
        
        private fun updateUserPassword(username: String, encodedPassword: String) {
            // Update password in database
        }
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=0}
fun good_case_12() {
    @Configuration
    class SecurityConfig {
        @Bean
        fun authenticationProvider(): DaoAuthenticationProvider {
            val provider = DaoAuthenticationProvider()
            provider.setUserDetailsService(userDetailsService())
            // ok: kotlin-weak-password-encoder
            provider.setPasswordEncoder(SCryptPasswordEncoder())
            return provider
        }
        
        @Bean
        fun userDetailsService(): UserDetailsService {
            // Return user details service
            return InMemoryUserDetailsManager()
        }
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=0}
fun good_case_13() {
    class UserRegistrationService {
        fun registerUser(username: String, password: String) {
            // ok: kotlin-weak-password-encoder
            val encoder = BCryptPasswordEncoder()
            val encodedPassword = encoder.encode(password)
            
            val user = User(username, encodedPassword, emptyList())
            saveUser(user)
        }
        
        private fun saveUser(user: User) {
            // Save user to database
        }
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=0}
fun good_case_14() {
    class PasswordMigrationService {
        fun migratePasswords() {
            val users = getAllUsers()
            
            // ok: kotlin-weak-password-encoder
            val newEncoder = Argon2PasswordEncoder(16, 32, 1, 16384, 2)
            
            for (user in users) {
                // Migrate passwords using strong encoder
                val decodedPassword = decodePassword(user.password)
                val reEncodedPassword = newEncoder.encode(decodedPassword)
                updateUserPassword(user.id, reEncodedPassword)
            }
        }
        
        private fun getAllUsers(): List<User> = listOf()
        private fun decodePassword(password: String): String = ""
        private fun updateUserPassword(id: Int, password: String) {}
    }
}
// {/fact}

// {fact rule=weak-password-encoding@v1.0 defects=0}
fun good_case_15() {
    class CustomSecurityConfig {
        fun configureGlobal(auth: AuthenticationManagerBuilder) {
            // ok: kotlin-weak-password-encoder
            val encoder = BCryptPasswordEncoder(10)
            
            auth.inMemoryAuthentication()
                .withUser("admin")
                .password(encoder.encode("adminPass"))
                .roles("ADMIN")
                .and()
                .withUser("user")
                .password(encoder.encode("userPass"))
                .roles("USER")
        }
    }
}
// {/fact}

// Helper function for examples
private fun createUserDetailsService(): UserDetailsService {
    return InMemoryUserDetailsManager()
}

// Helper classes for examples
class UserService {
    fun setPasswordEncoder(encoder: PasswordEncoder) {}
}

class User(val username: String, val password: String, val roles: List<String>) {
    val id: Int = 1
    
    companion object {
        fun builder(): UserBuilder {
            return UserBuilder()
        }
        
        fun withUsername(username: String): UserBuilder {
            return UserBuilder().username(username)
        }
    }
    
    class UserBuilder {
        private var username: String = ""
        private var password: String = ""
        private var roles: List<String> = listOf()
        
        fun username(username: String): UserBuilder {
            this.username = username
            return this
        }
        
        fun password(password: String): UserBuilder {
            this.password = password
            return this
        }
        
        fun roles(vararg roles: String): UserBuilder {
            this.roles = roles.toList()
            return this
        }
        
        fun build(): User {
            return User(username, password, roles)
        }
    }
}