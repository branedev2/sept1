import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.util.Scanner
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.web.bind.annotation.*
import org.springframework.stereotype.Controller
import org.apache.commons.text.StringEscapeUtils
import java.util.regex.Pattern

// True Positives (Vulnerable Code)

@Controller
class CommandInjectionExamples {

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
    @RequestMapping("/bad1")
    fun bad_case_1(request: HttpServletRequest, response: HttpServletResponse) {
        val userInput = request.getParameter("command")
        
        // ruleid: kotlin-command-injection
        val process = Runtime.getRuntime().exec("ls -la $userInput")
        
        val reader = BufferedReader(InputStreamReader(process.inputStream))
        var line: String?
        val output = StringBuilder()
        
        while (reader.readLine().also { line = it } != null) {
            output.append(line).append("\n")
        }
        
        response.writer.write(output.toString())
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
    @GetMapping("/bad2")
    fun bad_case_2(@RequestParam filename: String): String {
        val command = "cat /tmp/$filename"
        
        // ruleid: kotlin-command-injection
        val process = ProcessBuilder(command.split(" ")).start()
        
        val scanner = Scanner(process.inputStream).useDelimiter("\\A")
        return if (scanner.hasNext()) scanner.next() else ""
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
    @PostMapping("/bad3")
    fun bad_case_3(@RequestBody payload: Map<String, String>): String {
        val host = payload["host"]
        
        // ruleid: kotlin-command-injection
        val process = Runtime.getRuntime().exec(arrayOf("ping", "-c", "4", host))
        
        val reader = BufferedReader(InputStreamReader(process.inputStream))
        return reader.readText()
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
    @GetMapping("/bad4")
    fun bad_case_4(request: HttpServletRequest): String {
        val fileName = request.getParameter("file")
        val dir = request.getParameter("dir")
        
        // ruleid: kotlin-command-injection
        val process = Runtime.getRuntime().exec("find $dir -name $fileName")
        
        return BufferedReader(InputStreamReader(process.inputStream)).readText()
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
    @RequestMapping("/bad5")
    fun bad_case_5(request: HttpServletRequest): String {
        val ipAddress = request.getParameter("ip")
        val command = StringBuilder()
        command.append("ping -c 4 ")
        command.append(ipAddress)
        
        // ruleid: kotlin-command-injection
        val process = Runtime.getRuntime().exec(command.toString())
        
        return BufferedReader(InputStreamReader(process.inputStream)).readText()
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
    @GetMapping("/bad6")
    fun bad_case_6(@RequestParam username: String): String {
        // ruleid: kotlin-command-injection
        val process = ProcessBuilder("sh", "-c", "grep $username /etc/passwd").start()
        
        return BufferedReader(InputStreamReader(process.inputStream)).readText()
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
    @PostMapping("/bad7")
    fun bad_case_7(@RequestBody data: Map<String, String>): String {
        val command = data["command"] ?: "ls"
        val args = data["args"] ?: ""
        
        // ruleid: kotlin-command-injection
        val fullCommand = "$command $args"
        val process = Runtime.getRuntime().exec(fullCommand)
        
        return BufferedReader(InputStreamReader(process.inputStream)).readText()
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
    @GetMapping("/bad8")
    fun bad_case_8(request: HttpServletRequest): String {
        val userDir = request.getParameter("dir")
        val userFile = request.getParameter("file")
        val commandParts = arrayOf("find", userDir, "-name", userFile)
        
        // ruleid: kotlin-command-injection
        val process = Runtime.getRuntime().exec(commandParts)
        
        return BufferedReader(InputStreamReader(process.inputStream)).readText()
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
    @RequestMapping("/bad9")
    fun bad_case_9(request: HttpServletRequest): String {
        val scriptName = request.getParameter("script")
        val scriptArgs = request.getParameter("args")
        
        // ruleid: kotlin-command-injection
        val process = Runtime.getRuntime().exec("python $scriptName $scriptArgs")
        
        return BufferedReader(InputStreamReader(process.inputStream)).readText()
    }
// {/fact}

    @GetMapping("/bad10")
    fun bad_case_10(@RequestHeader("X-Command") command: String): String {
        // ruleid: kotlin-command-injection
        val process = ProcessBuilder().command("bash", "-c", command).start()
        
        return BufferedReader(InputStreamReader(process.inputStream)).readText()
    }

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
    @PostMapping("/bad11")
    fun bad_case_11(@RequestBody data: Map<String, String>): String {
        val userInput = data["input"] ?: ""
        val commandList = mutableListOf("ls", "-la")
        commandList.add(userInput)
        
        // ruleid: kotlin-command-injection
        val process = ProcessBuilder(commandList).start()
        
        return BufferedReader(InputStreamReader(process.inputStream)).readText()
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
    @GetMapping("/bad12")
    fun bad_case_12(request: HttpServletRequest): String {
        val userCommand = request.getParameter("cmd")
        val userArgs = request.getParameter("args")
        
        // ruleid: kotlin-command-injection
        val process = Runtime.getRuntime().exec("$userCommand $userArgs")
        
        return BufferedReader(InputStreamReader(process.inputStream)).readText()
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
    @RequestMapping("/bad13")
    fun bad_case_13(request: HttpServletRequest): String {
        val path = request.getParameter("path")
        val format = request.getParameter("format")
        val command = when (format) {
            "long" -> "ls -la $path"
            else -> "ls $path"
        }
        
        // ruleid: kotlin-command-injection
        val process = Runtime.getRuntime().exec(command)
        
        return BufferedReader(InputStreamReader(process.inputStream)).readText()
    }
// {/fact}

    @GetMapping("/bad14")
    fun bad_case_14(@CookieValue("command") command: String): String {
        // ruleid: kotlin-command-injection
        val process = Runtime.getRuntime().exec(command)
        
        return BufferedReader(InputStreamReader(process.inputStream)).readText()
    }

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
    @PostMapping("/bad15")
    fun bad_case_15(@RequestParam options: String): String {
        val baseCommand = "tar"
        
        // ruleid: kotlin-command-injection
        val process = Runtime.getRuntime().exec("$baseCommand $options")
        
        return BufferedReader(InputStreamReader(process.inputStream)).readText()
    }
// {/fact}

    // True Negatives (Safe Code)

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
    @GetMapping("/good1")
    fun good_case_1(@RequestParam filename: String): String {
        val allowedFiles = listOf("users.txt", "config.txt", "data.csv")
        
        // ok: kotlin-command-injection
        if (allowedFiles.contains(filename)) {
            val process = Runtime.getRuntime().exec("cat /tmp/$filename")
            return BufferedReader(InputStreamReader(process.inputStream)).readText()
        }
        
        return "File not allowed"
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
    @PostMapping("/good2")
    fun good_case_2(@RequestBody data: Map<String, String>): String {
        val command = when (data["action"]) {
            "list" -> "ls -la"
            "disk" -> "df -h"
            "memory" -> "free -m"
            else -> "echo 'Invalid command'"
        }
        
        // ok: kotlin-command-injection
        val process = Runtime.getRuntime().exec(command)
        
        return BufferedReader(InputStreamReader(process.inputStream)).readText()
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
    @GetMapping("/good3")
    fun good_case_3(request: HttpServletRequest): String {
        val userInput = request.getParameter("command")
        val sanitizedInput = StringEscapeUtils.escapeJava(userInput)
        
        // ok: kotlin-command-injection
        val process = Runtime.getRuntime().exec("echo $sanitizedInput")
        
        return BufferedReader(InputStreamReader(process.inputStream)).readText()
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
    @RequestMapping("/good4")
    fun good_case_4(request: HttpServletRequest): String {
        val ipAddress = request.getParameter("ip")
        val ipPattern = Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")
        
        if (ipPattern.matcher(ipAddress).matches()) {
            // ok: kotlin-command-injection
            val process = Runtime.getRuntime().exec(arrayOf("ping", "-c", "4", ipAddress))
            return BufferedReader(InputStreamReader(process.inputStream)).readText()
        }
        
        return "Invalid IP address"
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
    @GetMapping("/good5")
    fun good_case_5(@RequestParam option: String): String {
        val allowedOptions = mapOf(
            "disk" to "df -h",
            "memory" to "free -m",
            "cpu" to "top -bn1"
        )
        
        val command = allowedOptions[option] ?: "echo 'Invalid option'"
        
        // ok: kotlin-command-injection
        val process = Runtime.getRuntime().exec(command)
        
        return BufferedReader(InputStreamReader(process.inputStream)).readText()
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
    @PostMapping("/good6")
    fun good_case_6(@RequestBody data: Map<String, String>): String {
        val filename = data["filename"] ?: ""
        
        // Validate filename with regex to prevent path traversal and command injection
        val validFilenamePattern = Pattern.compile("^[a-zA-Z0-9_-]+\\.(txt|log|csv)$")
        
        if (validFilenamePattern.matcher(filename).matches()) {
            // ok: kotlin-command-injection
            val process = Runtime.getRuntime().exec(arrayOf("cat", "/var/logs/$filename"))
            return BufferedReader(InputStreamReader(process.inputStream)).readText()
        }
        
        return "Invalid filename"
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
    @GetMapping("/good7")
    fun good_case_7(request: HttpServletRequest): String {
        // Using ProcessBuilder with separate arguments prevents command injection
        val processBuilder = ProcessBuilder("ls", "-la", "/tmp")
        
        // ok: kotlin-command-injection
        val process = processBuilder.start()
        
        return BufferedReader(InputStreamReader(process.inputStream)).readText()
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
    @RequestMapping("/good8")
    fun good_case_8(request: HttpServletRequest): String {
        val userDir = request.getParameter("dir")
        
        // Validate directory path
        if (!userDir.contains("..") && !userDir.contains("&") && !userDir.contains("|") && !userDir.contains(";")) {
            // ok: kotlin-command-injection
            val process = ProcessBuilder("ls", "-la", userDir).start()
            return BufferedReader(InputStreamReader(process.inputStream)).readText()
        }
        
        return "Invalid directory path"
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
    @GetMapping("/good9")
    fun good_case_9(@RequestParam command: String): String {
        // Using a switch statement to map user input to safe commands
        val safeCommand = when (command) {
            "list_files" -> arrayOf("ls", "-la")
            "disk_space" -> arrayOf("df", "-h")
            "memory_usage" -> arrayOf("free", "-m")
            else -> arrayOf("echo", "Unknown command")
        }
        
        // ok: kotlin-command-injection
        val process = Runtime.getRuntime().exec(safeCommand)
        
        return BufferedReader(InputStreamReader(process.inputStream)).readText()
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
    @PostMapping("/good10")
    fun good_case_10(@RequestBody data: Map<String, String>): String {
        val fileName = data["file"] ?: ""
        val baseDir = "/var/data/"
        
        // Ensure we don't allow path traversal
        val file = java.io.File(baseDir)
        val canonicalBasePath = file.canonicalPath
        
        val requestedFile = java.io.File(baseDir, fileName)
        val canonicalRequestedPath = requestedFile.canonicalPath
        
        if (canonicalRequestedPath.startsWith(canonicalBasePath)) {
            // ok: kotlin-command-injection
            val process = Runtime.getRuntime().exec(arrayOf("cat", canonicalRequestedPath))
            return BufferedReader(InputStreamReader(process.inputStream)).readText()
        }
        
        return "Access denied"
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
    @GetMapping("/good11")
    fun good_case_11(request: HttpServletRequest): String {
        // Using Java's built-in file operations instead of executing commands
        // ok: kotlin-command-injection
        val fileContent = java.io.File("/etc/hostname").readText()
        return fileContent
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
    @RequestMapping("/good12")
    fun good_case_12(request: HttpServletRequest): String {
        val action = request.getParameter("action")
        
        // Using a predefined set of commands
        val commandMap = mapOf(
            "uptime" to arrayOf("uptime"),
            "hostname" to arrayOf("hostname"),
            "date" to arrayOf("date")
        )
        
        val command = commandMap[action]
        
        if (command != null) {
            // ok: kotlin-command-injection
            val process = Runtime.getRuntime().exec(command)
            return BufferedReader(InputStreamReader(process.inputStream)).readText()
        }
        
        return "Invalid action"
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
    @GetMapping("/good13")
    fun good_case_13(@RequestParam format: String): String {
        // Using string interpolation with validated input
        val validFormats = setOf("json", "xml", "text")
        
        if (format in validFormats) {
            // ok: kotlin-command-injection
            val process = Runtime.getRuntime().exec(arrayOf("echo", "Format: $format"))
            return BufferedReader(InputStreamReader(process.inputStream)).readText()
        }
        
        return "Invalid format"
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
    @PostMapping("/good14")
    fun good_case_14(@RequestBody data: Map<String, List<String>>): String {
        val files = data["files"] ?: listOf()
        val allowedDir = "/var/logs/"
        
        // Validate all files are in the allowed directory and have valid extensions
        val validFiles = files.filter { 
            it.matches(Regex("^[a-zA-Z0-9_-]+\\.(log|txt)$")) && 
            !it.contains("..") 
        }
        
        if (validFiles.size == files.size) {
            // ok: kotlin-command-injection
            val process = ProcessBuilder("ls", "-la", *validFiles.map { "$allowedDir$it" }.toTypedArray()).start()
            return BufferedReader(InputStreamReader(process.inputStream)).readText()
        }
        
        return "Invalid file selection"
    }
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
    @GetMapping("/good15")
    fun good_case_15(request: HttpServletRequest): String {
        // Using a custom function to execute commands safely
        // ok: kotlin-command-injection
        return executeCommand("hostname")
    }
// {/fact}
    
    private fun executeCommand(command: String): String {
        val allowedCommands = setOf("hostname", "date", "uptime", "whoami")
        
        if (command in allowedCommands) {
            val process = Runtime.getRuntime().exec(command)
            return BufferedReader(InputStreamReader(process.inputStream)).readText()
        }
        
        return "Command not allowed"
    }
}