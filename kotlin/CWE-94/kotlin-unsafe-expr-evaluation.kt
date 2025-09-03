import org.apache.commons.jexl3.JexlBuilder
import org.apache.commons.jexl3.JexlContext
import org.apache.commons.jexl3.JexlExpression
import org.apache.commons.jexl3.MapContext
import org.springframework.expression.ExpressionParser
import org.springframework.expression.spel.standard.SpelExpressionParser
import org.springframework.expression.spel.support.StandardEvaluationContext
import org.owasp.esapi.ESAPI
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.web.bind.annotation.*
import org.springframework.stereotype.Controller
import java.util.regex.Pattern

@Controller
class ExpressionEvaluationController {

    // True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/jexl/vulnerable1")
    fun bad_case_1(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("expr")
        val jexl = JexlBuilder().create()
        // ruleid: kotlin-unsafe-expr-evaluation
        val expression = jexl.createExpression(userInput)
        val context = MapContext()
        val result = expression.evaluate(context)
        response.writer.write("Result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/jexl/vulnerable2")
    fun bad_case_2(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("command")
        val jexl = JexlBuilder().create()
        val context = MapContext()
        context.set("user", "admin")
        // ruleid: kotlin-unsafe-expr-evaluation
        val expr = jexl.createExpression(userInput)
        val result = expr.evaluate(context)
        response.writer.write("Command executed with result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/spel/vulnerable1")
    fun bad_case_3(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("query")
        val parser = SpelExpressionParser()
        val context = StandardEvaluationContext()
        // ruleid: kotlin-unsafe-expr-evaluation
        val expression = parser.parseExpression(userInput)
        val result = expression.getValue(context)
        response.writer.write("Query result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @RequestMapping("/jexl/vulnerable3")
    fun bad_case_4(request: HttpServletRequest, response: HttpServletResponse) {
        val jexlEngine = JexlBuilder().silent(false).strict(true).create()
        val userInput = request.getHeader("X-Expression")
        val context = MapContext()
        context.set("data", mapOf("key" to "value"))
        // ruleid: kotlin-unsafe-expr-evaluation
        val expr = jexlEngine.createExpression(userInput)
        val result = expr.evaluate(context)
        response.writer.write("Header expression result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/spel/vulnerable2")
    fun bad_case_5(request: HttpServletRequest, response: HttpServletResponse) {
        val parser = SpelExpressionParser()
        val context = StandardEvaluationContext(UserData("admin", "password"))
        val userInput = request.getParameter("spelExpr")
        // ruleid: kotlin-unsafe-expr-evaluation
        val expr = parser.parseExpression(userInput)
        val result = expr.getValue(context)
        response.writer.write("Result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/jexl/vulnerable4")
    fun bad_case_6(request: HttpServletRequest, response: HttpServletResponse) {
        val jexl = JexlBuilder().create()
        val userInput = request.getParameter("formula")
        val context = MapContext()
        context.set("x", 10)
        context.set("y", 20)
        // ruleid: kotlin-unsafe-expr-evaluation
        val expression = jexl.createExpression(userInput)
        val result = expression.evaluate(context)
        response.writer.write("Formula result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/spel/vulnerable3")
    fun bad_case_7(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getReader().readLine()
        val parser = SpelExpressionParser()
        val context = StandardEvaluationContext()
        context.setVariable("systemProps", System.getProperties())
        // ruleid: kotlin-unsafe-expr-evaluation
        val expression = parser.parseExpression(userInput)
        val result = expression.getValue(context)
        response.writer.write("Expression result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/jexl/vulnerable5")
    fun bad_case_8(request: HttpServletRequest, response: HttpServletResponse) {
        val cookie = request.cookies?.find { it.name == "userExpression" }
        val userInput = cookie?.value ?: "1+1"
        val jexl = JexlBuilder().create()
        val context = MapContext()
        // ruleid: kotlin-unsafe-expr-evaluation
        val expression = jexl.createExpression(userInput)
        val result = expression.evaluate(context)
        response.writer.write("Cookie expression result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/spel/vulnerable4")
    fun bad_case_9(request: HttpServletRequest, response: HttpServletResponse) {
        val parser = SpelExpressionParser()
        val context = StandardEvaluationContext()
        val userInput = request.getParameter("template")
        val processedInput = "#{$userInput}" // Adding template markers doesn't make it safe
        // ruleid: kotlin-unsafe-expr-evaluation
        val expression = parser.parseExpression(processedInput)
        val result = expression.getValue(context)
        response.writer.write("Template result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/jexl/vulnerable6")
    fun bad_case_10(request: HttpServletRequest, response: HttpServletResponse) {
        val jexl = JexlBuilder().create()
        val userInput = request.getParameter("calc")
        val partialSanitized = userInput.replace("'", "") // Incomplete sanitization
        val context = MapContext()
        // ruleid: kotlin-unsafe-expr-evaluation
        val expression = jexl.createExpression(partialSanitized)
        val result = expression.evaluate(context)
        response.writer.write("Calculation result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/spel/vulnerable5")
    fun bad_case_11(request: HttpServletRequest, response: HttpServletResponse) {
        val parser = SpelExpressionParser()
        val context = StandardEvaluationContext()
        val userInput = request.getParameter("expression")
        val modifiedInput = "\"$userInput\"" // Adding quotes doesn't make it safe
        // ruleid: kotlin-unsafe-expr-evaluation
        val expression = parser.parseExpression(modifiedInput)
        val result = expression.getValue(context)
        response.writer.write("Modified expression result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/jexl/vulnerable7")
    fun bad_case_12(request: HttpServletRequest, response: HttpServletResponse) {
        val jexl = JexlBuilder().create()
        val baseExpression = "x + y + "
        val userInput = request.getParameter("z")
        val fullExpression = baseExpression + userInput // Concatenating with user input is still unsafe
        val context = MapContext()
        context.set("x", 5)
        context.set("y", 10)
        // ruleid: kotlin-unsafe-expr-evaluation
        val expression = jexl.createExpression(fullExpression)
        val result = expression.evaluate(context)
        response.writer.write("Combined expression result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/spel/vulnerable6")
    fun bad_case_13(request: HttpServletRequest, response: HttpServletResponse) {
        val parser = SpelExpressionParser()
        val context = StandardEvaluationContext()
        val userInputMap = request.parameterMap
        val userInput = userInputMap["expr"]?.get(0) ?: "1+1"
        // ruleid: kotlin-unsafe-expr-evaluation
        val expression = parser.parseExpression(userInput)
        val result = expression.getValue(context)
        response.writer.write("Parameter map expression result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @GetMapping("/jexl/vulnerable8")
    fun bad_case_14(request: HttpServletRequest, response: HttpServletResponse) {
        val jexl = JexlBuilder().create()
        val userInput = request.getRequestURI().substring(request.getRequestURI().lastIndexOf('/') + 1)
        val context = MapContext()
        // ruleid: kotlin-unsafe-expr-evaluation
        val expression = jexl.createExpression(userInput)
        val result = expression.evaluate(context)
        response.writer.write("URI-based expression result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/spel/vulnerable7")
    fun bad_case_15(request: HttpServletRequest, response: HttpServletResponse) {
        val parser = SpelExpressionParser()
        val context = StandardEvaluationContext()
        val requestBody = request.reader.lines().reduce("", { a, b -> a + b })
        // ruleid: kotlin-unsafe-expr-evaluation
        val expression = parser.parseExpression(requestBody)
        val result = expression.getValue(context)
        response.writer.write("Request body expression result: $result")
    }
// {/fact}

    // True Negative Examples (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/jexl/safe1")
    fun good_case_1(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("expr")
        val jexl = JexlBuilder().create()
        // ok: kotlin-unsafe-expr-evaluation
        val sanitizedInput = ESAPI.encoder().encodeForJava(userInput)
        val expression = jexl.createExpression(sanitizedInput)
        val context = MapContext()
        val result = expression.evaluate(context)
        response.writer.write("Result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/jexl/safe2")
    fun good_case_2(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("command")
        // ok: kotlin-unsafe-expr-evaluation
        val allowedExpressions = listOf("1+1", "2*2", "10-5")
        if (!allowedExpressions.contains(userInput)) {
            response.writer.write("Invalid expression")
            return
        }
        
        val jexl = JexlBuilder().create()
        val expression = jexl.createExpression(userInput)
        val context = MapContext()
        val result = expression.evaluate(context)
        response.writer.write("Result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/spel/safe1")
    fun good_case_3(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("query")
        // ok: kotlin-unsafe-expr-evaluation
        val pattern = Pattern.compile("^[0-9+\\-*/()\\s]+$")
        if (!pattern.matcher(userInput).matches()) {
            response.writer.write("Invalid expression")
            return
        }
        
        val parser = SpelExpressionParser()
        val expression = parser.parseExpression(userInput)
        val context = StandardEvaluationContext()
        val result = expression.getValue(context)
        response.writer.write("Result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @RequestMapping("/jexl/safe3")
    fun good_case_4(request: HttpServletRequest, response: HttpServletResponse) {
        // ok: kotlin-unsafe-expr-evaluation
        val safeExpression = "user.name + ' has role: ' + user.role"
        val jexl = JexlBuilder().create()
        val expression = jexl.createExpression(safeExpression)
        val context = MapContext()
        context.set("user", mapOf("name" to "John", "role" to "admin"))
        val result = expression.evaluate(context)
        response.writer.write("Result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/spel/safe2")
    fun good_case_5(request: HttpServletRequest, response: HttpServletResponse) {
        val parser = SpelExpressionParser()
        val context = StandardEvaluationContext()
        // ok: kotlin-unsafe-expr-evaluation
        val safeExpression = "'Hello, ' + #name"
        val expression = parser.parseExpression(safeExpression)
        context.setVariable("name", request.getParameter("name"))
        val result = expression.getValue(context)
        response.writer.write("Result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/jexl/safe4")
    fun good_case_6(request: HttpServletRequest, response: HttpServletResponse) {
        val jexl = JexlBuilder().create()
        val userInput = request.getParameter("formula")
        // ok: kotlin-unsafe-expr-evaluation
        val sanitizedInput = ESAPI.encoder().encodeForJava(userInput)
        val whitelistPattern = Pattern.compile("^[0-9+\\-*/()\\s.]+$")
        if (!whitelistPattern.matcher(sanitizedInput).matches()) {
            response.writer.write("Invalid formula")
            return
        }
        
        val expression = jexl.createExpression(sanitizedInput)
        val context = MapContext()
        val result = expression.evaluate(context)
        response.writer.write("Result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/spel/safe3")
    fun good_case_7(request: HttpServletRequest, response: HttpServletResponse) {
        // ok: kotlin-unsafe-expr-evaluation
        val templateMap = mapOf(
            "greeting" to "'Hello, ' + #name",
            "farewell" to "'Goodbye, ' + #name",
            "welcome" to "'Welcome to our site, ' + #name"
        )
        
        val templateKey = request.getParameter("template")
        val selectedTemplate = templateMap[templateKey] ?: "'Hello, ' + #name"
        
        val parser = SpelExpressionParser()
        val context = StandardEvaluationContext()
        context.setVariable("name", request.getParameter("name"))
        
        val expression = parser.parseExpression(selectedTemplate)
        val result = expression.getValue(context)
        response.writer.write("Result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/jexl/safe5")
    fun good_case_8(request: HttpServletRequest, response: HttpServletResponse) {
        val jexl = JexlBuilder().create()
        // ok: kotlin-unsafe-expr-evaluation
        val hardcodedExpression = "x * y + z"
        val expression = jexl.createExpression(hardcodedExpression)
        
        val context = MapContext()
        context.set("x", request.getParameter("x")?.toIntOrNull() ?: 0)
        context.set("y", request.getParameter("y")?.toIntOrNull() ?: 0)
        context.set("z", request.getParameter("z")?.toIntOrNull() ?: 0)
        
        val result = expression.evaluate(context)
        response.writer.write("Result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/spel/safe4")
    fun good_case_9(request: HttpServletRequest, response: HttpServletResponse) {
        val parser = SpelExpressionParser()
        val context = StandardEvaluationContext()
        
        val operation = request.getParameter("operation")
        // ok: kotlin-unsafe-expr-evaluation
        val safeExpressions = mapOf(
            "add" to "#a + #b",
            "subtract" to "#a - #b",
            "multiply" to "#a * #b",
            "divide" to "#a / #b"
        )
        
        val selectedExpression = safeExpressions[operation] ?: "#a + #b"
        val expression = parser.parseExpression(selectedExpression)
        
        context.setVariable("a", request.getParameter("a")?.toDoubleOrNull() ?: 0.0)
        context.setVariable("b", request.getParameter("b")?.toDoubleOrNull() ?: 0.0)
        
        val result = expression.getValue(context)
        response.writer.write("Result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/jexl/safe6")
    fun good_case_10(request: HttpServletRequest, response: HttpServletResponse) {
        val jexl = JexlBuilder().create()
        val userInput = request.getParameter("expr")
        
        // ok: kotlin-unsafe-expr-evaluation
        val sanitizer = ExpressionSanitizer()
        val safeExpression = sanitizer.sanitize(userInput)
        
        val expression = jexl.createExpression(safeExpression)
        val context = MapContext()
        val result = expression.evaluate(context)
        response.writer.write("Result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/spel/safe5")
    fun good_case_11(request: HttpServletRequest, response: HttpServletResponse) {
        val parser = SpelExpressionParser()
        val context = StandardEvaluationContext()
        
        // ok: kotlin-unsafe-expr-evaluation
        val staticExpression = "'User ' + #username + ' has permissions: ' + #permissions.toString()"
        val expression = parser.parseExpression(staticExpression)
        
        context.setVariable("username", request.getParameter("username"))
        context.setVariable("permissions", listOf("read", "write"))
        
        val result = expression.getValue(context)
        response.writer.write("Result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/jexl/safe7")
    fun good_case_12(request: HttpServletRequest, response: HttpServletResponse) {
        val jexl = JexlBuilder().create()
        
        // ok: kotlin-unsafe-expr-evaluation
        val expressionTemplate = "a + b"
        val expression = jexl.createExpression(expressionTemplate)
        
        val context = MapContext()
        context.set("a", request.getParameter("a")?.toIntOrNull() ?: 0)
        context.set("b", request.getParameter("b")?.toIntOrNull() ?: 0)
        
        val result = expression.evaluate(context)
        response.writer.write("Result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/spel/safe6")
    fun good_case_13(request: HttpServletRequest, response: HttpServletResponse) {
        val parser = SpelExpressionParser()
        val context = StandardEvaluationContext()
        
        val userInput = request.getParameter("expr")
        // ok: kotlin-unsafe-expr-evaluation
        if (userInput != null) {
            val sanitizedInput = ESAPI.encoder().encodeForJava(userInput)
            val validator = ExpressionValidator()
            if (!validator.isValid(sanitizedInput)) {
                response.writer.write("Invalid expression")
                return
            }
            
            val expression = parser.parseExpression(sanitizedInput)
            val result = expression.getValue(context)
            response.writer.write("Result: $result")
        }
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @GetMapping("/jexl/safe8")
    fun good_case_14(request: HttpServletRequest, response: HttpServletResponse) {
        val jexl = JexlBuilder().create()
        
        // ok: kotlin-unsafe-expr-evaluation
        val expressions = mapOf(
            "sum" to "a + b + c",
            "product" to "a * b * c",
            "average" to "(a + b + c) / 3"
        )
        
        val operation = request.getParameter("operation") ?: "sum"
        val selectedExpression = expressions[operation] ?: expressions["sum"]!!
        
        val expression = jexl.createExpression(selectedExpression)
        val context = MapContext()
        context.set("a", request.getParameter("a")?.toDoubleOrNull() ?: 0.0)
        context.set("b", request.getParameter("b")?.toDoubleOrNull() ?: 0.0)
        context.set("c", request.getParameter("c")?.toDoubleOrNull() ?: 0.0)
        
        val result = expression.evaluate(context)
        response.writer.write("Result: $result")
    }
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/spel/safe7")
    fun good_case_15(request: HttpServletRequest, response: HttpServletResponse) {
        val parser = SpelExpressionParser()
        val context = StandardEvaluationContext()
        
        // ok: kotlin-unsafe-expr-evaluation
        val configuredExpression = "T(java.lang.Math).max(#a, #b)"
        val expression = parser.parseExpression(configuredExpression)
        
        context.setVariable("a", request.getParameter("a")?.toIntOrNull() ?: 0)
        context.setVariable("b", request.getParameter("b")?.toIntOrNull() ?: 0)
        
        val result = expression.getValue(context)
        response.writer.write("Result: $result")
    }
// {/fact}
}

// Helper classes for the examples
class UserData(val username: String, val password: String)

class ExpressionSanitizer {
    fun sanitize(input: String?): String {
        if (input == null) return "0"
        val sanitized = ESAPI.encoder().encodeForJava(input)
        return if (Pattern.compile("^[0-9+\\-*/()\\s.]+$").matcher(sanitized).matches()) sanitized else "0"
    }
}

class ExpressionValidator {
    fun isValid(input: String): Boolean {
        return Pattern.compile("^[0-9+\\-*/()\\s.]+$").matcher(input).matches()
    }
}