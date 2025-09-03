package com.example.beanvalidation

import javax.validation.ConstraintValidator
import javax.validation.ConstraintValidatorContext
import javax.servlet.http.HttpServletRequest
import org.springframework.web.bind.annotation.*
import org.springframework.stereotype.Controller
import org.springframework.validation.annotation.Validated
import org.apache.commons.text.StringEscapeUtils
import org.owasp.esapi.ESAPI
import javax.validation.Constraint
import javax.validation.Payload
import kotlin.reflect.KClass
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.request.ServletRequestAttributes
import java.io.Serializable

// Custom annotation for validation
@Target(AnnotationTarget.FIELD, AnnotationTarget.PROPERTY_GETTER)
@Retention(AnnotationRetention.RUNTIME)
@Constraint(validatedBy = [CustomValidator::class])
annotation class CustomConstraint(
    val message: String = "Invalid input",
    val groups: Array<KClass<*>> = [],
    val payload: Array<KClass<out Payload>> = []
)

// Custom validator class
class CustomValidator : ConstraintValidator<CustomConstraint, String> {
    override fun initialize(constraintAnnotation: CustomConstraint) {}
    
    override fun isValid(value: String?, context: ConstraintValidatorContext): Boolean {
        // Validation logic
        return true
    }
}

// Entity class
data class User(
    @CustomConstraint
    val username: String,
    val email: String
)

// Controller for handling requests
@Controller
@RequestMapping("/api")
class ValidationController {
    
    @Autowired
    lateinit var request: HttpServletRequest
    
    // True Positive Examples (Vulnerable Code)
    
// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/validate1")
    fun bad_case_1(): String {
        val input = request.getParameter("errorMessage")
        val context = getValidatorContext()
        
        // ruleid: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(input)
            .addConstraintViolation()
        
        return "Validation failed"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/validate2")
    fun bad_case_2(): String {
        val userInput = request.getParameter("message")
        val context = getValidatorContext()
        
        // ruleid: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(userInput)
            .addPropertyNode("username")
            .addConstraintViolation()
        
        return "Processed"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/validate3")
    fun bad_case_3(): String {
        val headerValue = request.getHeader("X-Error-Message")
        val context = getValidatorContext()
        
        // ruleid: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(headerValue)
            .addPropertyNode("field")
            .addConstraintViolation()
        
        return "Validation completed"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/validate4")
    fun bad_case_4(): String {
        val context = getValidatorContext()
        val userInput = request.getParameter("customError")
        val processedInput = "Error: $userInput"
        
        // ruleid: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(processedInput)
            .addConstraintViolation()
        
        return "Processed with error"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/validate5")
    fun bad_case_5(): String {
        val context = getValidatorContext()
        val errorMsg = request.getParameter("errorCode")
        
        if (errorMsg.isNotEmpty()) {
            // ruleid: kotlin-insecure-bean-validation
            context.buildConstraintViolationWithTemplate(errorMsg)
                .addPropertyNode("code")
                .addConstraintViolation()
        }
        
        return "Validation with condition"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/validate6")
    fun bad_case_6(): String {
        val context = getValidatorContext()
        val params = request.parameterMap
        val errorMessage = params["error"]?.get(0) ?: "Default error"
        
        // ruleid: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(errorMessage)
            .addConstraintViolation()
        
        return "Processed parameter map"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/validate7")
    fun bad_case_7(): String {
        val context = getValidatorContext()
        val cookie = request.cookies?.firstOrNull { it.name == "errorTemplate" }
        val errorTemplate = cookie?.value ?: "Default error"
        
        // ruleid: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(errorTemplate)
            .addPropertyNode("cookie")
            .addConstraintViolation()
        
        return "Cookie-based validation"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/validate8")
    fun bad_case_8(): String {
        val context = getValidatorContext()
        val session = request.getSession()
        val storedError = session.getAttribute("errorMsg") as? String ?: "Default error"
        
        // ruleid: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(storedError)
            .addConstraintViolation()
        
        return "Session-based validation"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/validate9")
    fun bad_case_9(): String {
        val context = getValidatorContext()
        val errorParts = arrayOf(
            request.getParameter("errorPrefix"),
            request.getParameter("errorSuffix")
        )
        val combinedError = errorParts.joinToString(" ")
        
        // ruleid: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(combinedError)
            .addConstraintViolation()
        
        return "Combined error template"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/validate10")
    fun bad_case_10(): String {
        val context = getValidatorContext()
        val requestURI = request.requestURI
        val errorMsg = "Error occurred at: $requestURI with input: ${request.getParameter("input")}"
        
        // ruleid: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(errorMsg)
            .addConstraintViolation()
        
        return "URI-based error"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/validate11")
    fun bad_case_11(): String {
        val context = getValidatorContext()
        val errorMap = mutableMapOf<String, String>()
        errorMap["message"] = request.getParameter("errorMessage") ?: "Default"
        
        // ruleid: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(errorMap["message"])
            .addConstraintViolation()
        
        return "Map-based error"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/validate12")
    fun bad_case_12(): String {
        val context = getValidatorContext()
        val userAgent = request.getHeader("User-Agent")
        val errorMsg = "Browser incompatibility: $userAgent"
        
        // ruleid: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(errorMsg)
            .addConstraintViolation()
        
        return "User-Agent based error"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/validate13")
    fun bad_case_13(): String {
        val context = getValidatorContext()
        val queryString = request.queryString ?: ""
        val errorMsg = "Invalid query: $queryString"
        
        // ruleid: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(errorMsg)
            .addConstraintViolation()
        
        return "Query-based error"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/validate14")
    fun bad_case_14(): String {
        val context = getValidatorContext()
        val referer = request.getHeader("Referer") ?: ""
        
        // ruleid: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate("Invalid referrer: $referer")
            .addConstraintViolation()
        
        return "Referer-based error"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/validate15")
    fun bad_case_15(): String {
        val context = getValidatorContext()
        val contentType = request.contentType ?: ""
        val acceptHeader = request.getHeader("Accept") ?: ""
        val errorMsg = "Content negotiation failed: $contentType, $acceptHeader"
        
        // ruleid: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(errorMsg)
            .addConstraintViolation()
        
        return "Content negotiation error"
    }
// {/fact}
    
    // True Negative Examples (Safe Code)
    
// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/safe1")
    fun good_case_1(): String {
        val input = request.getParameter("errorMessage")
        val context = getValidatorContext()
        val safeInput = StringEscapeUtils.escapeHtml4(input)
        
        // ok: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(safeInput)
            .addConstraintViolation()
        
        return "Safe validation"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/safe2")
    fun good_case_2(): String {
        val userInput = request.getParameter("message")
        val context = getValidatorContext()
        val safeInput = ESAPI.encoder().encodeForHTML(userInput)
        
        // ok: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(safeInput)
            .addPropertyNode("username")
            .addConstraintViolation()
        
        return "Safe processing"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/safe3")
    fun good_case_3(): String {
        val context = getValidatorContext()
        
        // ok: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate("Static error message")
            .addConstraintViolation()
        
        return "Static template"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/safe4")
    fun good_case_4(): String {
        val context = getValidatorContext()
        val errorCode = request.getParameter("code")
        
        val safeTemplate = when(errorCode) {
            "1" -> "Invalid username format"
            "2" -> "Email address required"
            "3" -> "Password too weak"
            else -> "Unknown error"
        }
        
        // ok: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(safeTemplate)
            .addConstraintViolation()
        
        return "Safe template selection"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/safe5")
    fun good_case_5(): String {
        val input = request.getParameter("errorMessage")
        val context = getValidatorContext()
        
        // Sanitize by removing all non-alphanumeric characters
        val safeInput = input.replace(Regex("[^A-Za-z0-9 ]"), "")
        
        // ok: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(safeInput)
            .addConstraintViolation()
        
        return "Regex sanitized input"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/safe6")
    fun good_case_6(): String {
        val context = getValidatorContext()
        val errorMsgId = request.getParameter("errorId")?.toIntOrNull() ?: 0
        
        val safeTemplate = getErrorMessageById(errorMsgId)
        
        // ok: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(safeTemplate)
            .addConstraintViolation()
        
        return "Safe message lookup"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/safe7")
    fun good_case_7(): String {
        val context = getValidatorContext()
        val headerValue = request.getHeader("X-Error-Message")
        
        // Sanitize by HTML encoding and limiting length
        val safeInput = StringEscapeUtils.escapeHtml4(headerValue).take(100)
        
        // ok: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(safeInput)
            .addPropertyNode("field")
            .addConstraintViolation()
        
        return "Length-limited safe input"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/safe8")
    fun good_case_8(): String {
        val context = getValidatorContext()
        val userInput = request.getParameter("customError")
        
        // Use a message template with a placeholder
        val safeTemplate = "Error occurred: \${validatedValue}"
        
        // ok: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(safeTemplate)
            .addConstraintViolation()
        
        return "Safe template with placeholder"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/safe9")
    fun good_case_9(): String {
        val context = getValidatorContext()
        
        // Use a resource bundle for messages
        val messageKey = "validation.error.format"
        
        // ok: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate("{$messageKey}")
            .addConstraintViolation()
        
        return "Resource bundle message"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/safe10")
    fun good_case_10(): String {
        val context = getValidatorContext()
        val errorMsg = request.getParameter("errorMessage")
        
        // Custom sanitization function
        val safeInput = sanitizeInput(errorMsg)
        
        // ok: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(safeInput)
            .addConstraintViolation()
        
        return "Custom sanitization"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/safe11")
    fun good_case_11(): String {
        val context = getValidatorContext()
        val errorCode = request.getParameter("code")
        
        // Validate that input only contains digits
        if (!errorCode.all { it.isDigit() }) {
            return "Invalid input"
        }
        
        val safeTemplate = "Error code: $errorCode"
        
        // ok: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(safeTemplate)
            .addConstraintViolation()
        
        return "Input validation"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/safe12")
    fun good_case_12(): String {
        val context = getValidatorContext()
        val errorType = request.getParameter("type")
        
        // Whitelist validation
        val allowedTypes = listOf("format", "missing", "invalid")
        if (errorType !in allowedTypes) {
            return "Invalid error type"
        }
        
        val safeTemplate = "Error of type: $errorType"
        
        // ok: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(safeTemplate)
            .addConstraintViolation()
        
        return "Whitelist validation"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/safe13")
    fun good_case_13(): String {
        val context = getValidatorContext()
        val userInput = request.getParameter("message")
        
        // Double sanitization for extra security
        val safeInput = StringEscapeUtils.escapeHtml4(
            ESAPI.encoder().encodeForHTML(userInput)
        )
        
        // ok: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(safeInput)
            .addConstraintViolation()
        
        return "Double sanitization"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/safe14")
    fun good_case_14(): String {
        val context = getValidatorContext()
        
        // Use a parameterized message with safe substitution
        val fieldName = StringEscapeUtils.escapeHtml4(request.getParameter("field"))
        val safeTemplate = "{javax.validation.constraints.NotEmpty.message}"
        
        // ok: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(safeTemplate)
            .addPropertyNode(fieldName)
            .addConstraintViolation()
        
        return "Safe parameterized message"
    }
// {/fact}
    
// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/safe15")
    fun good_case_15(): String {
        val context = getValidatorContext()
        val errorMsg = request.getParameter("errorMessage")
        
        // Use a completely different approach to avoid the issue
        context.disableDefaultConstraintViolation()
        
        // Create a custom message in a safe way
        val safeMessage = "Custom error: ${StringEscapeUtils.escapeHtml4(errorMsg)}"
        
        // ok: kotlin-insecure-bean-validation
        context.buildConstraintViolationWithTemplate(safeMessage)
            .addConstraintViolation()
        
        return "Alternative approach"
    }
// {/fact}
    
    // Helper methods
    private fun getValidatorContext(): ConstraintValidatorContext {
        // This is a mock implementation for example purposes
        return MockConstraintValidatorContext()
    }
    
    private fun getErrorMessageById(id: Int): String {
        return when(id) {
            1 -> "Username is required"
            2 -> "Email format is invalid"
            3 -> "Password must be at least 8 characters"
            else -> "Unknown error"
        }
    }
    
    private fun sanitizeInput(input: String?): String {
        if (input == null) return "null input"
        // Remove potentially dangerous characters
        val sanitized = input.replace("<", "&lt;")
                            .replace(">", "&gt;")
                            .replace("\"", "&quot;")
                            .replace("'", "&#x27;")
                            .replace("/", "&#x2F;")
        return sanitized.take(200) // Limit length
    }
}

// Mock implementation for example purposes
class MockConstraintValidatorContext : ConstraintValidatorContext {
    override fun getDefaultConstraintMessageTemplate(): String = ""
    override fun unwrap(type: Class<*>): Any? = null
    override fun disableDefaultConstraintViolation() {}
    override fun buildConstraintViolationWithTemplate(messageTemplate: String): ConstraintValidatorContext.ConstraintViolationBuilder {
        return MockConstraintViolationBuilder()
    }
}

class MockConstraintViolationBuilder : ConstraintValidatorContext.ConstraintViolationBuilder {
    override fun addConstraintViolation(): ConstraintValidatorContext = MockConstraintValidatorContext()
    override fun addNode(name: String): ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderDefinedContext {
        return MockNodeBuilderDefinedContext()
    }
    override fun addPropertyNode(name: String): ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderCustomizableContext {
        return MockNodeBuilderCustomizableContext()
    }
    override fun addBeanNode(): ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderCustomizableContext {
        return MockNodeBuilderCustomizableContext()
    }
    override fun addParameterNode(name: String): ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderDefinedContext {
        return MockNodeBuilderDefinedContext()
    }
    override fun addContainerElementNode(name: String, containerType: Class<*>, typeArgumentIndex: Int): ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderDefinedContext {
        return MockNodeBuilderDefinedContext()
    }
}

class MockNodeBuilderDefinedContext : ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderDefinedContext {
    override fun addConstraintViolation(): ConstraintValidatorContext = MockConstraintValidatorContext()
    override fun addNode(name: String): ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderDefinedContext {
        return this
    }
    override fun addPropertyNode(name: String): ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderCustomizableContext {
        return MockNodeBuilderCustomizableContext()
    }
    override fun addBeanNode(): ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderCustomizableContext {
        return MockNodeBuilderCustomizableContext()
    }
    override fun addContainerElementNode(name: String, containerType: Class<*>, typeArgumentIndex: Int): ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderDefinedContext {
        return this
    }
}

class MockNodeBuilderCustomizableContext : ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderCustomizableContext {
    override fun addConstraintViolation(): ConstraintValidatorContext = MockConstraintValidatorContext()
    override fun addNode(name: String): ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderDefinedContext {
        return MockNodeBuilderDefinedContext()
    }
    override fun addPropertyNode(name: String): ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderCustomizableContext {
        return this
    }
    override fun addBeanNode(): ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderCustomizableContext {
        return this
    }
    override fun addContainerElementNode(name: String, containerType: Class<*>, typeArgumentIndex: Int): ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderDefinedContext {
        return MockNodeBuilderDefinedContext()
    }
    override fun inIterable(): ConstraintValidatorContext.ConstraintViolationBuilder.NodeContextBuilder {
        return MockNodeContextBuilder()
    }
    override fun inContainer(containerType: Class<*>, typeArgumentIndex: Int): ConstraintValidatorContext.ConstraintViolationBuilder.NodeContextBuilder {
        return MockNodeContextBuilder()
    }
}

class MockNodeContextBuilder : ConstraintValidatorContext.ConstraintViolationBuilder.NodeContextBuilder {
    override fun atKey(key: Any): ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderDefinedContext {
        return MockNodeBuilderDefinedContext()
    }
    override fun atIndex(index: Int): ConstraintValidatorContext.ConstraintViolationBuilder.NodeBuilderDefinedContext {
        return MockNodeBuilderDefinedContext()
    }
}