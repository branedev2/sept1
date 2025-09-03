import java.io.File
import java.io.FileInputStream
import java.io.FileReader
import java.io.FileWriter
import java.nio.file.Files
import java.nio.file.Paths
import org.springframework.web.bind.annotation.*
import org.springframework.stereotype.Controller
import org.springframework.http.ResponseEntity
import org.apache.commons.io.FilenameUtils
import javax.servlet.http.HttpServletRequest
import io.ktor.application.*
import io.ktor.http.*
import io.ktor.request.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import org.jetbrains.exposed.sql.*
import java.util.regex.Pattern

// True Positive Examples (Vulnerable Code)

@Controller
class PathTraversalController {
    
// {fact rule=path-traversal@v1.0 defects=1}
    @GetMapping("/file")
    fun bad_case_1(@RequestParam filename: String): ResponseEntity<String> {
        // ruleid: kotlin-path-traversal
        val file = File("data/$filename")
        val content = file.readText()
        return ResponseEntity.ok(content)
    }
// {/fact}
    
// {fact rule=path-traversal@v1.0 defects=1}
    @PostMapping("/read-config")
    fun bad_case_2(request: HttpServletRequest): ResponseEntity<String> {
        val configName = request.getParameter("config")
        // ruleid: kotlin-path-traversal
        val configFile = File("/etc/app/configs/$configName")
        val content = configFile.readText()
        return ResponseEntity.ok(content)
    }
// {/fact}
    
// {fact rule=path-traversal@v1.0 defects=1}
    @GetMapping("/download")
    fun bad_case_3(@RequestParam path: String): ResponseEntity<ByteArray> {
        // ruleid: kotlin-path-traversal
        val fileBytes = Files.readAllBytes(Paths.get("user/files/$path"))
        return ResponseEntity.ok(fileBytes)
    }
// {/fact}
    
    @GetMapping("/view-log")
    fun bad_case_4(@RequestHeader("X-Log-File") logFile: String): ResponseEntity<String> {
        // ruleid: kotlin-path-traversal
        val reader = FileReader("logs/$logFile")
        val content = reader.readText()
        reader.close()
        return ResponseEntity.ok(content)
    }
    
// {fact rule=path-traversal@v1.0 defects=1}
    @PostMapping("/save-file")
    fun bad_case_5(request: HttpServletRequest): ResponseEntity<String> {
        val filePath = request.getParameter("path")
        val content = request.getParameter("content")
        
        // ruleid: kotlin-path-traversal
        val writer = FileWriter(filePath)
        writer.write(content)
        writer.close()
        
        return ResponseEntity.ok("File saved")
    }
// {/fact}
}

class KtorPathTraversalExamples {
    fun configureRouting() = routing {
        get("/api/document") {
            val docPath = call.request.queryParameters["path"]
            // ruleid: kotlin-path-traversal
            val file = File("documents/$docPath")
            val content = file.readText()
            call.respondText(content)
        }
        
        post("/api/write-data") {
            val params = call.receiveParameters()
            val fileName = params["filename"]
            val data = params["data"]
            
            // ruleid: kotlin-path-traversal
            val outputFile = File("data/user_files/$fileName")
            outputFile.writeText(data ?: "")
            
            call.respondText("Data written successfully")
        }
    }
    
// {fact rule=path-traversal@v1.0 defects=1}
    fun bad_case_8() {
        embeddedServer(Netty, port = 8080) {
            routing {
                get("/read-profile") {
                    val username = call.request.queryParameters["user"]
                    // ruleid: kotlin-path-traversal
                    val profilePath = "profiles/$username/info.json"
                    val profileData = File(profilePath).readText()
                    call.respondText(profileData)
                }
            }
        }.start(wait = true)
    }
// {/fact}
}

@Controller
class MorePathTraversalExamples {
// {fact rule=path-traversal@v1.0 defects=1}
    @GetMapping("/load-template")
    fun bad_case_9(@RequestParam template: String): ResponseEntity<String> {
        // ruleid: kotlin-path-traversal
        val templateFile = FileInputStream("templates/$template")
        val content = templateFile.readBytes().toString(Charsets.UTF_8)
        templateFile.close()
        return ResponseEntity.ok(content)
    }
// {/fact}
    
// {fact rule=path-traversal@v1.0 defects=1}
    @PostMapping("/append-log")
    fun bad_case_10(request: HttpServletRequest): ResponseEntity<String> {
        val logName = request.getParameter("log")
        val message = request.getParameter("message")
        
        // ruleid: kotlin-path-traversal
        val logFile = File("app_logs/$logName")
        logFile.appendText("$message\n")
        
        return ResponseEntity.ok("Log updated")
    }
// {/fact}
    
// {fact rule=path-traversal@v1.0 defects=1}
    @GetMapping("/user-data")
    fun bad_case_11(@RequestParam userId: String, @RequestParam file: String): ResponseEntity<ByteArray> {
        val basePath = "user_data"
        val userPath = "$userId/$file"
        
        // ruleid: kotlin-path-traversal
        val userData = Files.readAllBytes(Paths.get(basePath, userPath))
        return ResponseEntity.ok(userData)
    }
// {/fact}
    
    @GetMapping("/config-file")
    fun bad_case_12(@RequestHeader("X-Config") configPath: String): ResponseEntity<String> {
        // ruleid: kotlin-path-traversal
        val configContent = File("configs/$configPath").readText()
        return ResponseEntity.ok(configContent)
    }
    
// {fact rule=path-traversal@v1.0 defects=1}
    @PostMapping("/create-directory")
    fun bad_case_13(request: HttpServletRequest): ResponseEntity<String> {
        val dirPath = request.getParameter("directory")
        
        // ruleid: kotlin-path-traversal
        val newDir = File("user_content/$dirPath")
        newDir.mkdirs()
        
        return ResponseEntity.ok("Directory created")
    }
// {/fact}
    
// {fact rule=path-traversal@v1.0 defects=1}
    @GetMapping("/serve-image")
    fun bad_case_14(@RequestParam imagePath: String): ResponseEntity<ByteArray> {
        // ruleid: kotlin-path-traversal
        val imageFile = File("images/$imagePath")
        val imageBytes = imageFile.readBytes()
        
        return ResponseEntity.ok(imageBytes)
    }
// {/fact}
    
// {fact rule=path-traversal@v1.0 defects=1}
    @PostMapping("/delete-file")
    fun bad_case_15(request: HttpServletRequest): ResponseEntity<String> {
        val fileToDelete = request.getParameter("file")
        
        // ruleid: kotlin-path-traversal
        val file = File("temp/$fileToDelete")
        file.delete()
        
        return ResponseEntity.ok("File deleted")
    }
// {/fact}
}

// True Negative Examples (Safe Code)

@Controller
class SafePathHandlingController {
    
// {fact rule=path-traversal@v1.0 defects=0}
    @GetMapping("/file-safe")
    fun good_case_1(@RequestParam filename: String): ResponseEntity<String> {
        // Sanitize the filename to prevent path traversal
        // ok: kotlin-path-traversal
        val sanitizedFilename = FilenameUtils.getName(filename)
        val file = File("data/$sanitizedFilename")
        val content = file.readText()
        return ResponseEntity.ok(content)
    }
// {/fact}
    
// {fact rule=path-traversal@v1.0 defects=0}
    @PostMapping("/read-config-safe")
    fun good_case_2(request: HttpServletRequest): ResponseEntity<String> {
        val configName = request.getParameter("config")
        
        // Validate against a whitelist of allowed config files
        val allowedConfigs = listOf("app.conf", "settings.conf", "users.conf")
        
        // ok: kotlin-path-traversal
        if (allowedConfigs.contains(configName)) {
            val configFile = File("/etc/app/configs/$configName")
            val content = configFile.readText()
            return ResponseEntity.ok(content)
        }
        
        return ResponseEntity.badRequest().body("Invalid config file")
    }
// {/fact}
    
// {fact rule=path-traversal@v1.0 defects=0}
    @GetMapping("/download-safe")
    fun good_case_3(@RequestParam path: String): ResponseEntity<ByteArray> {
        // Normalize the path and ensure it doesn't escape the intended directory
        // ok: kotlin-path-traversal
        val normalizedPath = FilenameUtils.normalize(path)
        if (normalizedPath == null || normalizedPath.contains("..")) {
            return ResponseEntity.badRequest().body("Invalid path".toByteArray())
        }
        
        val fileBytes = Files.readAllBytes(Paths.get("user/files/$normalizedPath"))
        return ResponseEntity.ok(fileBytes)
    }
// {/fact}
    
    @GetMapping("/view-log-safe")
    fun good_case_4(@RequestHeader("X-Log-File") logFile: String): ResponseEntity<String> {
        // Use regex to ensure only valid log filenames are accepted
        val logFilePattern = Pattern.compile("^[a-zA-Z0-9_-]+\\.log$")
        
        // ok: kotlin-path-traversal
        if (!logFilePattern.matcher(logFile).matches()) {
            return ResponseEntity.badRequest().body("Invalid log file name")
        }
        
        val reader = FileReader("logs/$logFile")
        val content = reader.readText()
        reader.close()
        return ResponseEntity.ok(content)
    }
    
// {fact rule=path-traversal@v1.0 defects=0}
    @PostMapping("/save-file-safe")
    fun good_case_5(request: HttpServletRequest): ResponseEntity<String> {
        val fileName = request.getParameter("filename")
        val content = request.getParameter("content")
        
        // Sanitize filename and restrict to a specific directory
        // ok: kotlin-path-traversal
        val sanitizedFileName = FilenameUtils.getName(fileName)
        val baseDir = File("user_files")
        val targetFile = File(baseDir, sanitizedFileName)
        
        // Ensure the resulting file is within the intended directory
        if (!targetFile.canonicalPath.startsWith(baseDir.canonicalPath)) {
            return ResponseEntity.badRequest().body("Invalid file path")
        }
        
        val writer = FileWriter(targetFile)
        writer.write(content)
        writer.close()
        
        return ResponseEntity.ok("File saved")
    }
// {/fact}
}

class SafeKtorPathHandlingExamples {
    fun configureRouting() = routing {
        get("/api/document-safe") {
            val docPath = call.request.queryParameters["path"]
            
            // Validate path against allowed patterns
            // ok: kotlin-path-traversal
            val validPathPattern = Pattern.compile("^[a-zA-Z0-9_/-]+\\.(txt|pdf|doc)$")
            if (docPath == null || !validPathPattern.matcher(docPath).matches()) {
                call.respondText("Invalid document path", status = HttpStatusCode.BadRequest)
                return@get
            }
            
            val file = File("documents/$docPath")
            val content = file.readText()
            call.respondText(content)
        }
        
        post("/api/write-data-safe") {
            val params = call.receiveParameters()
            val fileName = params["filename"] ?: ""
            val data = params["data"] ?: ""
            
            // Sanitize filename and ensure it's just a filename, not a path
            // ok: kotlin-path-traversal
            val sanitizedFileName = FilenameUtils.getName(fileName)
            if (sanitizedFileName.isEmpty() || sanitizedFileName != fileName) {
                call.respondText("Invalid filename", status = HttpStatusCode.BadRequest)
                return@post
            }
            
            val outputFile = File("data/user_files/$sanitizedFileName")
            outputFile.writeText(data)
            
            call.respondText("Data written successfully")
        }
    }
    
// {fact rule=path-traversal@v1.0 defects=0}
    fun good_case_8() {
        embeddedServer(Netty, port = 8080) {
            routing {
                get("/read-profile-safe") {
                    val username = call.request.queryParameters["user"]
                    
                    // Validate username format to prevent path traversal
                    // ok: kotlin-path-traversal
                    val usernamePattern = Pattern.compile("^[a-zA-Z0-9_]+$")
                    if (username == null || !usernamePattern.matcher(username).matches()) {
                        call.respondText("Invalid username", status = HttpStatusCode.BadRequest)
                        return@get
                    }
                    
                    val profilePath = "profiles/$username/info.json"
                    val profileData = File(profilePath).readText()
                    call.respondText(profileData)
                }
            }
        }.start(wait = true)
    }
// {/fact}
}

@Controller
class MoreSafePathHandlingExamples {
// {fact rule=path-traversal@v1.0 defects=0}
    @GetMapping("/load-template-safe")
    fun good_case_9(@RequestParam template: String): ResponseEntity<String> {
        // Use a whitelist of allowed templates
        val allowedTemplates = setOf("welcome.html", "profile.html", "settings.html")
        
        // ok: kotlin-path-traversal
        if (!allowedTemplates.contains(template)) {
            return ResponseEntity.badRequest().body("Invalid template")
        }
        
        val templateFile = FileInputStream("templates/$template")
        val content = templateFile.readBytes().toString(Charsets.UTF_8)
        templateFile.close()
        return ResponseEntity.ok(content)
    }
// {/fact}
    
// {fact rule=path-traversal@v1.0 defects=0}
    @PostMapping("/append-log-safe")
    fun good_case_10(request: HttpServletRequest): ResponseEntity<String> {
        val logName = request.getParameter("log")
        val message = request.getParameter("message")
        
        // Normalize and validate log name
        // ok: kotlin-path-traversal
        val normalizedLogName = FilenameUtils.normalize(logName)
        if (normalizedLogName == null || !normalizedLogName.endsWith(".log") || normalizedLogName.contains("/")) {
            return ResponseEntity.badRequest().body("Invalid log name")
        }
        
        val logFile = File("app_logs/$normalizedLogName")
        logFile.appendText("$message\n")
        
        return ResponseEntity.ok("Log updated")
    }
// {/fact}
    
// {fact rule=path-traversal@v1.0 defects=0}
    @GetMapping("/user-data-safe")
    fun good_case_11(@RequestParam userId: String, @RequestParam file: String): ResponseEntity<ByteArray> {
        // Validate userId and file parameters
        val userIdPattern = Pattern.compile("^[a-zA-Z0-9_]+$")
        val filePattern = Pattern.compile("^[a-zA-Z0-9_.-]+$")
        
        // ok: kotlin-path-traversal
        if (!userIdPattern.matcher(userId).matches() || !filePattern.matcher(file).matches()) {
            return ResponseEntity.badRequest().body("Invalid parameters".toByteArray())
        }
        
        val basePath = "user_data"
        val userPath = "$userId/$file"
        
        val userData = Files.readAllBytes(Paths.get(basePath, userPath))
        return ResponseEntity.ok(userData)
    }
// {/fact}
    
    @GetMapping("/config-file-safe")
    fun good_case_12(@RequestHeader("X-Config") configPath: String): ResponseEntity<String> {
        // Validate config path against a whitelist
        val allowedConfigs = mapOf(
            "app" to "app.json",
            "system" to "system.json",
            "network" to "network.json"
        )
        
        // ok: kotlin-path-traversal
        val actualConfigFile = allowedConfigs[configPath]
        if (actualConfigFile == null) {
            return ResponseEntity.badRequest().body("Invalid config requested")
        }
        
        val configContent = File("configs/$actualConfigFile").readText()
        return ResponseEntity.ok(configContent)
    }
    
// {fact rule=path-traversal@v1.0 defects=0}
    @PostMapping("/create-directory-safe")
    fun good_case_13(request: HttpServletRequest): ResponseEntity<String> {
        val dirPath = request.getParameter("directory")
        
        // Validate directory name
        val dirPattern = Pattern.compile("^[a-zA-Z0-9_-]+$")
        
        // ok: kotlin-path-traversal
        if (!dirPattern.matcher(dirPath).matches()) {
            return ResponseEntity.badRequest().body("Invalid directory name")
        }
        
        val newDir = File("user_content/$dirPath")
        newDir.mkdirs()
        
        return ResponseEntity.ok("Directory created")
    }
// {/fact}
    
// {fact rule=path-traversal@v1.0 defects=0}
    @GetMapping("/serve-image-safe")
    fun good_case_14(@RequestParam imagePath: String): ResponseEntity<ByteArray> {
        // Normalize and validate the image path
        // ok: kotlin-path-traversal
        val normalizedPath = FilenameUtils.normalize(imagePath)
        if (normalizedPath == null || normalizedPath.contains("..")) {
            return ResponseEntity.badRequest().body("Invalid image path".toByteArray())
        }
        
        // Additional validation to ensure it's an image file
        if (!normalizedPath.matches(".*\\.(jpg|jpeg|png|gif)$".toRegex())) {
            return ResponseEntity.badRequest().body("Invalid image format".toByteArray())
        }
        
        val imageFile = File("images/$normalizedPath")
        val imageBytes = imageFile.readBytes()
        
        return ResponseEntity.ok(imageBytes)
    }
// {/fact}
    
// {fact rule=path-traversal@v1.0 defects=0}
    @PostMapping("/delete-file-safe")
    fun good_case_15(request: HttpServletRequest): ResponseEntity<String> {
        val fileToDelete = request.getParameter("file")
        
        // Sanitize and validate the filename
        // ok: kotlin-path-traversal
        val sanitizedFilename = FilenameUtils.getName(fileToDelete)
        if (sanitizedFilename.isEmpty() || sanitizedFilename != fileToDelete) {
            return ResponseEntity.badRequest().body("Invalid filename")
        }
        
        val file = File("temp/$sanitizedFilename")
        
        // Additional check to ensure the file is within the intended directory
        val tempDir = File("temp").canonicalPath
        if (!file.canonicalPath.startsWith(tempDir)) {
            return ResponseEntity.badRequest().body("Invalid file path")
        }
        
        file.delete()
        
        return ResponseEntity.ok("File deleted")
    }
// {/fact}
}