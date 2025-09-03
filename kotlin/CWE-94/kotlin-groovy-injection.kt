import org.codehaus.groovy.control.CompilerConfiguration
import groovy.lang.GroovyShell
import groovy.lang.Binding
import groovy.lang.GroovyClassLoader
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.web.bind.annotation.*
import org.springframework.stereotype.Controller
import org.springframework.http.ResponseEntity
import org.owasp.html.PolicyFactory
import org.owasp.html.Sanitizers
import java.util.regex.Pattern
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

@Controller
class GroovyInjectionExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/bad1")
    fun bad_case_1(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("script")
        val shell = GroovyShell()
        // ruleid: kotlin-groovy-injection
        val result = shell.evaluate(userInput)
        response.writer.write("Result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/bad2")
    fun bad_case_2(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("expression")
        val binding = Binding()
        binding.setVariable("x", 10)
        val shell = GroovyShell(binding)
        // ruleid: kotlin-groovy-injection
        val result = shell.evaluate(userInput)
        response.writer.write("Calculated: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/bad3")
    fun bad_case_3(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getHeader("X-Groovy-Script")
        val config = CompilerConfiguration()
        val shell = GroovyShell(config)
        try {
            // ruleid: kotlin-groovy-injection
            val result = shell.evaluate(userInput)
            response.writer.write("Executed: $result")
        } catch (e: Exception) {
            response.writer.write("Error: ${e.message}")
        }
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @RequestMapping("/bad4", method = [RequestMethod.GET, RequestMethod.POST])
    fun bad_case_4(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("code")
        if (userInput != null && userInput.isNotEmpty()) {
            val binding = Binding()
            binding.setVariable("request", request)
            val shell = GroovyShell(binding)
            // ruleid: kotlin-groovy-injection
            val result = shell.evaluate(userInput)
            response.writer.write("Output: $result")
        }
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/bad5")
    fun bad_case_5(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.cookies?.find { it.name == "groovyScript" }?.value ?: ""
        val decodedInput = URLDecoder.decode(userInput, StandardCharsets.UTF_8.name())
        val shell = GroovyShell()
        // ruleid: kotlin-groovy-injection
        val result = shell.evaluate(decodedInput)
        response.writer.write("Cookie script result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/bad6")
    fun bad_case_6(@RequestBody payload: Map<String, String>, response: HttpServletResponse) {
        val userScript = payload["script"] ?: return
        val shell = GroovyShell()
        // ruleid: kotlin-groovy-injection
        val result = shell.evaluate(userScript)
        response.writer.write("JSON script result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/bad7")
    fun bad_case_7(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("template")
        val binding = Binding()
        binding.setVariable("name", "User")
        val shell = GroovyShell(binding)
        
        try {
            // ruleid: kotlin-groovy-injection
            val renderedTemplate = shell.evaluate("\"\"\"${userInput}\"\"\"")
            response.writer.write(renderedTemplate.toString())
        } catch (e: Exception) {
            response.writer.write("Template error: ${e.message}")
        }
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/bad8")
    fun bad_case_8(request: HttpServletRequest, response: HttpServletResponse) {
        val scriptName = request.getParameter("scriptName")
        val scriptArgs = request.getParameter("scriptArgs")
        
        val binding = Binding()
        binding.setVariable("args", scriptArgs.split(","))
        val shell = GroovyShell(binding)
        
        // ruleid: kotlin-groovy-injection
        val result = shell.evaluate("def run() { ${scriptName}(args) }; run()")
        response.writer.write("Function result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/bad9")
    fun bad_case_9(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("calculation")
        
        // Simple validation that doesn't prevent injection
        if (!userInput.contains("System") && !userInput.contains("exec")) {
            val shell = GroovyShell()
            // ruleid: kotlin-groovy-injection
            val result = shell.evaluate(userInput)
            response.writer.write("Calculation result: $result")
        } else {
            response.writer.write("Invalid input")
        }
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/bad10")
    fun bad_case_10(@RequestParam formData: Map<String, String>, response: HttpServletResponse) {
        val userScript = formData["userScript"] ?: return
        val userVars = formData["variables"]?.split(",") ?: emptyList()
        
        val binding = Binding()
        userVars.forEach { binding.setVariable(it, true) }
        
        val shell = GroovyShell(binding)
        // ruleid: kotlin-groovy-injection
        val result = shell.evaluate(userScript)
        response.writer.write("Script with variables result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/bad11")
    fun bad_case_11(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("query")
        val gcl = GroovyClassLoader()
        
        try {
            // ruleid: kotlin-groovy-injection
            val groovyClass = gcl.parseClass(userInput)
            val instance = groovyClass.newInstance()
            response.writer.write("Created instance: ${instance.toString()}")
        } catch (e: Exception) {
            response.writer.write("Error: ${e.message}")
        }
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/bad12")
    fun bad_case_12(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("expression")
        
        // Attempt to filter but still vulnerable
        val filteredInput = userInput.replace("System.exit", "")
                                    .replace("Runtime.exec", "")
        
        val shell = GroovyShell()
        // ruleid: kotlin-groovy-injection
        val result = shell.evaluate(filteredInput)
        response.writer.write("Filtered result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/bad13")
    fun bad_case_13(request: HttpServletRequest, response: HttpServletResponse) {
        val baseScript = "def calculate(x, y) { return x + y }"
        val userInput = request.getParameter("additionalCode")
        
        val fullScript = "$baseScript\n$userInput\ncalculate(5, 10)"
        val shell = GroovyShell()
        // ruleid: kotlin-groovy-injection
        val result = shell.evaluate(fullScript)
        response.writer.write("Combined script result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/bad14")
    fun bad_case_14(request: HttpServletRequest, response: HttpServletResponse) {
        val scriptParts = mutableListOf<String>()
        scriptParts.add("def x = 10")
        scriptParts.add(request.getParameter("middlePart") ?: "")
        scriptParts.add("return x * 2")
        
        val fullScript = scriptParts.joinToString("\n")
        val shell = GroovyShell()
        // ruleid: kotlin-groovy-injection
        val result = shell.evaluate(fullScript)
        response.writer.write("Multi-part script result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/bad15")
    fun bad_case_15(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("dynamicMethod")
        val methodName = "process" + userInput.capitalize()
        
        val script = """
            class Helper {
                def $methodName() {
                    return "Processed by $methodName"
                }
            }
            new Helper().$methodName()
        """.trimIndent()
        
        val shell = GroovyShell()
        // ruleid: kotlin-groovy-injection
        val result = shell.evaluate(script)
        response.writer.write("Dynamic method result: $result")
    }
// {/fact}

    // True Negative Examples (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/good1")
    fun good_case_1(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("expression")
        
        // Whitelist of allowed expressions
        val allowedExpressions = mapOf(
            "add" to "2 + 2",
            "subtract" to "5 - 3",
            "multiply" to "4 * 3"
        )
        
        val safeScript = allowedExpressions[userInput] ?: "0"
        val shell = GroovyShell()
        // ok: kotlin-groovy-injection
        val result = shell.evaluate(safeScript)
        response.writer.write("Safe result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/good2")
    fun good_case_2(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("calculation")
        
        // Only allow numeric expressions with basic operators
        if (Pattern.matches("^[0-9+\\-*/().\\s]+$", userInput)) {
            val shell = GroovyShell()
            // ok: kotlin-groovy-injection
            val result = shell.evaluate(userInput)
            response.writer.write("Safe calculation: $result")
        } else {
            response.writer.write("Invalid input: only numbers and basic operators allowed")
        }
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/good3")
    fun good_case_3(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("template")
        
        // Use a sanitizer
        val policyFactory = Sanitizers.FORMATTING.and(Sanitizers.BLOCKS)
        val sanitized = policyFactory.sanitize(userInput)
        
        // Use the sanitized input as a string, not as code to evaluate
        val binding = Binding()
        binding.setVariable("template", sanitized)
        val shell = GroovyShell(binding)
        // ok: kotlin-groovy-injection
        val result = shell.evaluate("return \"Template content: \$template\"")
        response.writer.write(result.toString())
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/good4")
    fun good_case_4(request: HttpServletRequest, response: HttpServletResponse) {
        val operation = request.getParameter("operation")
        val x = request.getParameter("x")?.toIntOrNull() ?: 0
        val y = request.getParameter("y")?.toIntOrNull() ?: 0
        
        // Use a predefined script with parameters
        val script = """
            def calculate(op, a, b) {
                switch(op) {
                    case "add": return a + b
                    case "subtract": return a - b
                    case "multiply": return a * b
                    case "divide": return b != 0 ? a / b : 0
                    default: return 0
                }
            }
            calculate(operation, x, y)
        """.trimIndent()
        
        val binding = Binding()
        binding.setVariable("operation", operation)
        binding.setVariable("x", x)
        binding.setVariable("y", y)
        
        val shell = GroovyShell(binding)
        // ok: kotlin-groovy-injection
        val result = shell.evaluate(script)
        response.writer.write("Result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/good5")
    fun good_case_5(request: HttpServletRequest, response: HttpServletResponse) {
        val templateName = request.getParameter("template")
        
        // Use a map of predefined templates
        val templates = mapOf(
            "welcome" to "Welcome, \${name}!",
            "goodbye" to "Goodbye, \${name}!",
            "error" to "Error: \${message}"
        )
        
        val selectedTemplate = templates[templateName] ?: "No template selected"
        
        val binding = Binding()
        binding.setVariable("name", "User")
        binding.setVariable("message", "Unknown error")
        
        val shell = GroovyShell(binding)
        // ok: kotlin-groovy-injection
        val result = shell.evaluate("\"\"\"$selectedTemplate\"\"\"")
        response.writer.write(result.toString())
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/good6")
    fun good_case_6(request: HttpServletRequest, response: HttpServletResponse) {
        // Use a completely hardcoded script
        val script = """
            def factorial(n) {
                if (n <= 1) return 1
                else return n * factorial(n-1)
            }
            factorial(5)
        """.trimIndent()
        
        val shell = GroovyShell()
        // ok: kotlin-groovy-injection
        val result = shell.evaluate(script)
        response.writer.write("Factorial result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/good7")
    fun good_case_7(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("data")
        
        // Don't evaluate user input as code, use it as data
        val binding = Binding()
        binding.setVariable("userData", userInput)
        
        val script = """
            def processData(data) {
                return "Processed: " + data.toUpperCase()
            }
            processData(userData)
        """.trimIndent()
        
        val shell = GroovyShell(binding)
        // ok: kotlin-groovy-injection
        val result = shell.evaluate(script)
        response.writer.write(result.toString())
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/good8")
    fun good_case_8(request: HttpServletRequest, response: HttpServletResponse) {
        val userChoice = request.getParameter("choice")?.toIntOrNull() ?: 0
        
        // Use user input to select a predefined script
        val scripts = listOf(
            "return 'Option 1 selected'",
            "return 'Option 2 selected'",
            "return 'Option 3 selected'"
        )
        
        val safeIndex = userChoice.coerceIn(0, scripts.size - 1)
        val selectedScript = scripts[safeIndex]
        
        val shell = GroovyShell()
        // ok: kotlin-groovy-injection
        val result = shell.evaluate(selectedScript)
        response.writer.write(result.toString())
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/good9")
    fun good_case_9(request: HttpServletRequest, response: HttpServletResponse) {
        val userName = request.getParameter("name") ?: "Guest"
        val userAge = request.getParameter("age")?.toIntOrNull() ?: 0
        
        // Pass user input as variables, not as code
        val binding = Binding()
        binding.setVariable("name", userName)
        binding.setVariable("age", userAge)
        
        val script = """
            if (age < 18) {
                return "Sorry $name, you must be 18 or older"
            } else {
                return "Welcome, $name!"
            }
        """.trimIndent()
        
        val shell = GroovyShell(binding)
        // ok: kotlin-groovy-injection
        val result = shell.evaluate(script)
        response.writer.write(result.toString())
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/good10")
    fun good_case_10(request: HttpServletRequest, response: HttpServletResponse) {
        val jsonData = request.getParameter("jsonData") ?: "{}"
        
        // Process user data without evaluating it as code
        val binding = Binding()
        binding.setVariable("jsonString", jsonData)
        
        val script = """
            import groovy.json.JsonSlurper
            def slurper = new JsonSlurper()
            def data = slurper.parseText(jsonString)
            return "Parsed JSON with keys: " + data.keySet().join(", ")
        """.trimIndent()
        
        val shell = GroovyShell(binding)
        // ok: kotlin-groovy-injection
        val result = shell.evaluate(script)
        response.writer.write(result.toString())
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/good11")
    fun good_case_11(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("input") ?: ""
        
        // Instead of evaluating user input, process it directly in Kotlin
        val processedResult = when {
            userInput.isEmpty() -> "Empty input"
            userInput.length < 5 -> "Input too short"
            userInput.length > 20 -> "Input too long"
            else -> "Input accepted: $userInput"
        }
        
        response.writer.write(processedResult)
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/good12")
    fun good_case_12(request: HttpServletRequest, response: HttpServletResponse) {
        val mathOperation = request.getParameter("operation") ?: "add"
        val num1 = request.getParameter("num1")?.toDoubleOrNull() ?: 0.0
        val num2 = request.getParameter("num2")?.toDoubleOrNull() ?: 0.0
        
        // Use a safe approach with a predefined script and binding
        val binding = Binding()
        binding.setVariable("op", mathOperation)
        binding.setVariable("a", num1)
        binding.setVariable("b", num2)
        
        val script = """
            def calculator = [
                add: { x, y -> x + y },
                subtract: { x, y -> x - y },
                multiply: { x, y -> x * y },
                divide: { x, y -> y != 0 ? x / y : 0 }
            ]
            
            def operation = calculator[op] ?: calculator.add
            return operation(a, b)
        """.trimIndent()
        
        val shell = GroovyShell(binding)
        // ok: kotlin-groovy-injection
        val result = shell.evaluate(script)
        response.writer.write("Result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/good13")
    fun good_case_13(request: HttpServletRequest, response: HttpServletResponse) {
        val templateId = request.getParameter("templateId") ?: "default"
        val userName = request.getParameter("userName") ?: "Guest"
        
        // Use a template system with predefined templates
        val templates = mapOf(
            "default" to "Hello, \${userName}!",
            "welcome" to "Welcome to our site, \${userName}!",
            "premium" to "Thank you for being a premium member, \${userName}!"
        )
        
        val selectedTemplate = templates[templateId] ?: templates["default"]!!
        
        val binding = Binding()
        binding.setVariable("userName", userName)
        binding.setVariable("template", selectedTemplate)
        
        val script = """
            return template.replace("\${userName}", userName)
        """.trimIndent()
        
        val shell = GroovyShell(binding)
        // ok: kotlin-groovy-injection
        val result = shell.evaluate(script)
        response.writer.write(result.toString())
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/good14")
    fun good_case_14(request: HttpServletRequest, response: HttpServletResponse) {
        val configName = request.getParameter("config") ?: "default"
        
        // Use a configuration system with predefined configurations
        val configs = mapOf(
            "default" to mapOf("theme" to "light", "fontSize" to 12),
            "dark" to mapOf("theme" to "dark", "fontSize" to 14),
            "large" to mapOf("theme" to "light", "fontSize" to 18)
        )
        
        val selectedConfig = configs[configName] ?: configs["default"]!!
        
        val binding = Binding()
        binding.setVariable("config", selectedConfig)
        
        val script = """
            return "Selected config: theme=${config.theme}, fontSize=${config.fontSize}"
        """.trimIndent()
        
        val shell = GroovyShell(binding)
        // ok: kotlin-groovy-injection
        val result = shell.evaluate(script)
        response.writer.write(result.toString())
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/good15")
    fun good_case_15(request: HttpServletRequest, response: HttpServletResponse) {
        val reportType = request.getParameter("reportType") ?: "summary"
        val startDate = request.getParameter("startDate") ?: "2023-01-01"
        val endDate = request.getParameter("endDate") ?: "2023-12-31"
        
        // Use a secure approach with predefined report types and data binding
        val binding = Binding()
        binding.setVariable("reportType", reportType)
        binding.setVariable("startDate", startDate)
        binding.setVariable("endDate", endDate)
        
        val script = """
            def generateReport(type, start, end) {
                def reports = [
                    summary: { s, e -> "Summary report from ${s} to ${e}" },
                    detailed: { s, e -> "Detailed report from ${s} to ${e}" },
                    financial: { s, e -> "Financial report from ${s} to ${e}" }
                ]
                
                def generator = reports[type] ?: reports.summary
                return generator(start, end)
            }
            
            generateReport(reportType, startDate, endDate)
        """.trimIndent()
        
        val shell = GroovyShell(binding)
        // ok: kotlin-groovy-injection
        val result = shell.evaluate(script)
        response.writer.write(result.toString())
    }
// {/fact}
}