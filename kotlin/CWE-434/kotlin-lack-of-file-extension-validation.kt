import java.io.File
import java.nio.file.Files
import java.nio.file.Paths
import javax.servlet.http.HttpServletRequest
import org.springframework.web.bind.annotation.*
import org.springframework.web.multipart.MultipartFile
import org.springframework.stereotype.Controller
import org.springframework.http.ResponseEntity
import org.springframework.http.HttpStatus
import java.util.UUID
import javax.servlet.annotation.MultipartConfig
import javax.servlet.http.Part
import java.util.regex.Pattern

// TRUE POSITIVES (Vulnerable Code)

@Controller
class FileUploadController {
    
    @PostMapping("/upload1")
    fun bad_case_1(@RequestParam("file") file: MultipartFile): ResponseEntity<String> {
        val fileName = file.originalFilename
        val destinationPath = "/uploads/$fileName"
        
        // ruleid: kotlin-lack-of-file-extension-validation
        val targetFile = File(destinationPath)
        file.transferTo(targetFile)
        
        return ResponseEntity.ok("File uploaded successfully")
    }
    
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
    @PostMapping("/upload2")
    fun bad_case_2(request: HttpServletRequest): ResponseEntity<String> {
        val filePart = request.getPart("file")
        val fileName = filePart.submittedFileName
        val uploadDir = "/var/www/uploads/"
        
        // ruleid: kotlin-lack-of-file-extension-validation
        val targetPath = uploadDir + fileName
        Files.copy(filePart.inputStream, Paths.get(targetPath))
        
        return ResponseEntity.ok("File uploaded successfully")
    }
// {/fact}
    
    @PostMapping("/upload3")
    fun bad_case_3(@RequestParam("file") file: MultipartFile): ResponseEntity<String> {
        val originalName = file.originalFilename ?: "unknown"
        val uniqueName = UUID.randomUUID().toString() + "_" + originalName
        
        // ruleid: kotlin-lack-of-file-extension-validation
        val targetLocation = Paths.get("/opt/data/uploads/").resolve(uniqueName)
        Files.copy(file.inputStream, targetLocation)
        
        return ResponseEntity.ok("File uploaded as $uniqueName")
    }
    
    @PostMapping("/upload4")
    fun bad_case_4(@RequestParam("fileName") fileName: String, @RequestParam("fileContent") content: String): ResponseEntity<String> {
        // ruleid: kotlin-lack-of-file-extension-validation
        val file = File("/storage/$fileName")
        file.writeText(content)
        
        return ResponseEntity.ok("File created successfully")
    }
    
    @PostMapping("/profile-picture")
    fun bad_case_5(@RequestParam("image") image: MultipartFile): ResponseEntity<String> {
        val userId = "user123"
        val fileName = image.originalFilename ?: "profile.jpg"
        
        // ruleid: kotlin-lack-of-file-extension-validation
        val destinationFile = File("/user/profiles/$userId/$fileName")
        destinationFile.parentFile.mkdirs()
        image.transferTo(destinationFile)
        
        return ResponseEntity.ok("Profile picture updated")
    }
}

@Controller
class DocumentController {
    
    @PostMapping("/documents/upload")
    fun bad_case_6(@RequestParam("document") file: MultipartFile): ResponseEntity<String> {
        val fileName = file.originalFilename ?: "document"
        val timestamp = System.currentTimeMillis()
        val newFileName = "${timestamp}_$fileName"
        
        // ruleid: kotlin-lack-of-file-extension-validation
        val targetFile = File("/documents/$newFileName")
        file.transferTo(targetFile)
        
        return ResponseEntity.ok("Document uploaded")
    }
    
    @PostMapping("/batch-upload")
    fun bad_case_7(@RequestParam("files") files: Array<MultipartFile>): ResponseEntity<String> {
        for (file in files) {
            val fileName = file.originalFilename ?: continue
            
            // ruleid: kotlin-lack-of-file-extension-validation
            val targetPath = "/batch/uploads/$fileName"
            file.transferTo(File(targetPath))
        }
        
        return ResponseEntity.ok("Batch upload completed")
    }
    
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
    @PostMapping("/save-attachment")
    fun bad_case_8(request: HttpServletRequest): ResponseEntity<String> {
        val filePart: Part = request.getPart("attachment")
        val submittedName = filePart.submittedFileName
        
        // ruleid: kotlin-lack-of-file-extension-validation
        val outputFile = File("/attachments/$submittedName")
        filePart.inputStream.use { input ->
            outputFile.outputStream().use { output ->
                input.copyTo(output)
            }
        }
        
        return ResponseEntity.ok("Attachment saved")
    }
// {/fact}
    
    @PostMapping("/upload-with-rename")
    fun bad_case_9(@RequestParam("file") file: MultipartFile): ResponseEntity<String> {
        val originalName = file.originalFilename ?: "unnamed"
        val username = "current_user" // Normally from authentication
        val newFileName = "${username}_$originalName"
        
        // ruleid: kotlin-lack-of-file-extension-validation
        val targetPath = Paths.get("/user/files/$newFileName")
        Files.copy(file.inputStream, targetPath)
        
        return ResponseEntity.ok("File uploaded with custom name")
    }
    
    @PostMapping("/save-from-url")
    fun bad_case_10(@RequestParam("fileUrl") fileUrl: String, @RequestParam("fileName") fileName: String): ResponseEntity<String> {
        val url = java.net.URL(fileUrl)
        
        // ruleid: kotlin-lack-of-file-extension-validation
        val targetFile = File("/downloads/$fileName")
        url.openStream().use { input ->
            targetFile.outputStream().use { output ->
                input.copyTo(output)
            }
        }
        
        return ResponseEntity.ok("File downloaded and saved")
    }
}

@Controller
class MediaController {
    
    @PostMapping("/upload-media")
    fun bad_case_11(@RequestParam("media") file: MultipartFile): ResponseEntity<String> {
        val fileName = file.originalFilename ?: "media"
        val userId = "user456" // Would come from authentication
        
        // ruleid: kotlin-lack-of-file-extension-validation
        val mediaPath = "/media/$userId/$fileName"
        val targetFile = File(mediaPath)
        targetFile.parentFile.mkdirs()
        file.transferTo(targetFile)
        
        return ResponseEntity.ok("Media uploaded")
    }
    
    @PostMapping("/temp-upload")
    fun bad_case_12(@RequestParam("file") file: MultipartFile): ResponseEntity<String> {
        val tempFileName = "temp_" + file.originalFilename
        
        // ruleid: kotlin-lack-of-file-extension-validation
        val tempFile = File(System.getProperty("java.io.tmpdir"), tempFileName)
        file.transferTo(tempFile)
        
        return ResponseEntity.ok("File uploaded to temp directory")
    }
    
    @PostMapping("/process-csv")
    fun bad_case_13(@RequestParam("csvFile") file: MultipartFile): ResponseEntity<String> {
        val fileName = file.originalFilename ?: "data.csv"
        
        // ruleid: kotlin-lack-of-file-extension-validation
        val csvFile = File("/data/imports/$fileName")
        file.transferTo(csvFile)
        
        // Process CSV file...
        return ResponseEntity.ok("CSV processing started")
    }
    
    @PostMapping("/save-base64")
    fun bad_case_14(@RequestParam("base64Data") base64Data: String, @RequestParam("fileName") fileName: String): ResponseEntity<String> {
        val decodedData = java.util.Base64.getDecoder().decode(base64Data)
        
        // ruleid: kotlin-lack-of-file-extension-validation
        val outputFile = File("/uploads/$fileName")
        outputFile.writeBytes(decodedData)
        
        return ResponseEntity.ok("Base64 data saved as file")
    }
    
    @PostMapping("/upload-with-metadata")
    fun bad_case_15(@RequestParam("file") file: MultipartFile, @RequestParam("metadata") metadata: String): ResponseEntity<String> {
        val fileName = file.originalFilename ?: "unknown"
        
        // ruleid: kotlin-lack-of-file-extension-validation
        val targetFile = File("/storage/with-metadata/$fileName")
        file.transferTo(targetFile)
        
        // Save metadata separately
        File("/storage/with-metadata/$fileName.meta").writeText(metadata)
        
        return ResponseEntity.ok("File and metadata saved")
    }
}

// TRUE NEGATIVES (Secure Code)

@Controller
class SecureFileUploadController {
    
    private val ALLOWED_EXTENSIONS = listOf("jpg", "jpeg", "png", "gif")
    
    @PostMapping("/secure-upload1")
    fun good_case_1(@RequestParam("file") file: MultipartFile): ResponseEntity<String> {
        val fileName = file.originalFilename ?: return ResponseEntity.badRequest().body("No filename provided")
        
        // ok: kotlin-lack-of-file-extension-validation
        val extension = fileName.substringAfterLast('.', "").toLowerCase()
        if (extension !in ALLOWED_EXTENSIONS) {
            return ResponseEntity.badRequest().body("Invalid file extension")
        }
        
        val destinationPath = "/uploads/${UUID.randomUUID()}.$extension"
        val targetFile = File(destinationPath)
        file.transferTo(targetFile)
        
        return ResponseEntity.ok("File uploaded successfully")
    }
    
// {fact rule=unrestricted-file-upload@v1.0 defects=0}
    @PostMapping("/secure-upload2")
    fun good_case_2(request: HttpServletRequest): ResponseEntity<String> {
        val filePart = request.getPart("file")
        val fileName = filePart.submittedFileName ?: return ResponseEntity.badRequest().body("No filename provided")
        
        // ok: kotlin-lack-of-file-extension-validation
        val extension = fileName.substringAfterLast('.', "").toLowerCase()
        if (!ALLOWED_EXTENSIONS.contains(extension)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Unsupported file type")
        }
        
        val newFileName = "${UUID.randomUUID()}.$extension"
        val uploadDir = "/var/www/uploads/"
        val targetPath = uploadDir + newFileName
        Files.copy(filePart.inputStream, Paths.get(targetPath))
        
        return ResponseEntity.ok("File uploaded successfully as $newFileName")
    }
// {/fact}
    
    @PostMapping("/secure-upload3")
    fun good_case_3(@RequestParam("file") file: MultipartFile): ResponseEntity<String> {
        val originalName = file.originalFilename ?: return ResponseEntity.badRequest().body("No filename provided")
        
        // ok: kotlin-lack-of-file-extension-validation
        val extension = originalName.substringAfterLast('.', "").toLowerCase()
        if (extension !in setOf("pdf", "doc", "docx", "txt")) {
            return ResponseEntity.badRequest().body("Only PDF, DOC, DOCX, and TXT files are allowed")
        }
        
        val uniqueName = UUID.randomUUID().toString() + "." + extension
        val targetLocation = Paths.get("/opt/data/uploads/").resolve(uniqueName)
        Files.copy(file.inputStream, targetLocation)
        
        return ResponseEntity.ok("File uploaded as $uniqueName")
    }
    
    @PostMapping("/secure-upload4")
    fun good_case_4(@RequestParam("fileName") fileName: String, @RequestParam("fileContent") content: String): ResponseEntity<String> {
        // ok: kotlin-lack-of-file-extension-validation
        val extension = fileName.substringAfterLast('.', "").toLowerCase()
        if (extension !in listOf("txt", "log", "md")) {
            return ResponseEntity.badRequest().body("Only text files are allowed")
        }
        
        val safeFileName = UUID.randomUUID().toString() + "." + extension
        val file = File("/storage/$safeFileName")
        file.writeText(content)
        
        return ResponseEntity.ok("File created successfully as $safeFileName")
    }
    
    @PostMapping("/secure-profile-picture")
    fun good_case_5(@RequestParam("image") image: MultipartFile): ResponseEntity<String> {
        val userId = "user123"
        val fileName = image.originalFilename ?: return ResponseEntity.badRequest().body("No filename provided")
        
        // ok: kotlin-lack-of-file-extension-validation
        val extension = fileName.substringAfterLast('.', "").toLowerCase()
        if (extension !in listOf("jpg", "jpeg", "png")) {
            return ResponseEntity.badRequest().body("Only JPG and PNG images are allowed")
        }
        
        val safeFileName = "profile.$extension"
        val destinationFile = File("/user/profiles/$userId/$safeFileName")
        destinationFile.parentFile.mkdirs()
        image.transferTo(destinationFile)
        
        return ResponseEntity.ok("Profile picture updated")
    }
}

@Controller
class SecureDocumentController {
    
    @PostMapping("/secure-documents/upload")
    fun good_case_6(@RequestParam("document") file: MultipartFile): ResponseEntity<String> {
        val fileName = file.originalFilename ?: return ResponseEntity.badRequest().body("No filename provided")
        
        // ok: kotlin-lack-of-file-extension-validation
        val extension = fileName.substringAfterLast('.', "").toLowerCase()
        val allowedExtensions = setOf("pdf", "doc", "docx", "xls", "xlsx")
        
        if (extension !in allowedExtensions) {
            return ResponseEntity.badRequest().body("Invalid document type")
        }
        
        val timestamp = System.currentTimeMillis()
        val newFileName = "${timestamp}.$extension"
        val targetFile = File("/documents/$newFileName")
        file.transferTo(targetFile)
        
        return ResponseEntity.ok("Document uploaded as $newFileName")
    }
    
    @PostMapping("/secure-batch-upload")
    fun good_case_7(@RequestParam("files") files: Array<MultipartFile>): ResponseEntity<String> {
        val allowedExtensions = setOf("jpg", "png", "pdf")
        val uploadedFiles = mutableListOf<String>()
        
        for (file in files) {
            val fileName = file.originalFilename ?: continue
            
            // ok: kotlin-lack-of-file-extension-validation
            val extension = fileName.substringAfterLast('.', "").toLowerCase()
            if (extension !in allowedExtensions) {
                continue // Skip invalid files
            }
            
            val newFileName = "${UUID.randomUUID()}.$extension"
            val targetPath = "/batch/uploads/$newFileName"
            file.transferTo(File(targetPath))
            uploadedFiles.add(newFileName)
        }
        
        return ResponseEntity.ok("Batch upload completed. Uploaded ${uploadedFiles.size} files")
    }
    
// {fact rule=unrestricted-file-upload@v1.0 defects=0}
    @PostMapping("/secure-save-attachment")
    fun good_case_8(request: HttpServletRequest): ResponseEntity<String> {
        val filePart: Part = request.getPart("attachment")
        val submittedName = filePart.submittedFileName ?: return ResponseEntity.badRequest().body("No filename provided")
        
        // ok: kotlin-lack-of-file-extension-validation
        val extension = submittedName.substringAfterLast('.', "").toLowerCase()
        val allowedExtensions = listOf("pdf", "txt", "doc", "docx", "jpg", "png")
        
        if (extension !in allowedExtensions) {
            return ResponseEntity.badRequest().body("Unsupported attachment type")
        }
        
        val safeFileName = "${UUID.randomUUID()}.$extension"
        val outputFile = File("/attachments/$safeFileName")
        filePart.inputStream.use { input ->
            outputFile.outputStream().use { output ->
                input.copyTo(output)
            }
        }
        
        return ResponseEntity.ok("Attachment saved as $safeFileName")
    }
// {/fact}
    
    @PostMapping("/secure-upload-with-regex")
    fun good_case_9(@RequestParam("file") file: MultipartFile): ResponseEntity<String> {
        val originalName = file.originalFilename ?: return ResponseEntity.badRequest().body("No filename provided")
        
        // ok: kotlin-lack-of-file-extension-validation
        val extensionPattern = Pattern.compile("\\.(jpg|jpeg|png|gif)$", Pattern.CASE_INSENSITIVE)
        val matcher = extensionPattern.matcher(originalName)
        
        if (!matcher.find()) {
            return ResponseEntity.badRequest().body("Only image files are allowed")
        }
        
        val extension = matcher.group(1).toLowerCase()
        val newFileName = "${UUID.randomUUID()}.$extension"
        val targetPath = Paths.get("/user/files/$newFileName")
        Files.copy(file.inputStream, targetPath)
        
        return ResponseEntity.ok("Image uploaded as $newFileName")
    }
    
    @PostMapping("/secure-save-from-url")
    fun good_case_10(@RequestParam("fileUrl") fileUrl: String, @RequestParam("fileName") fileName: String): ResponseEntity<String> {
        // ok: kotlin-lack-of-file-extension-validation
        val extension = fileName.substringAfterLast('.', "").toLowerCase()
        val allowedExtensions = setOf("jpg", "jpeg", "png", "pdf")
        
        if (extension !in allowedExtensions) {
            return ResponseEntity.badRequest().body("Unsupported file type")
        }
        
        val safeFileName = "${UUID.randomUUID()}.$extension"
        val url = java.net.URL(fileUrl)
        val targetFile = File("/downloads/$safeFileName")
        
        url.openStream().use { input ->
            targetFile.outputStream().use { output ->
                input.copyTo(output)
            }
        }
        
        return ResponseEntity.ok("File downloaded and saved as $safeFileName")
    }
}

@Controller
class SecureMediaController {
    
    @PostMapping("/secure-upload-media")
    fun good_case_11(@RequestParam("media") file: MultipartFile): ResponseEntity<String> {
        val fileName = file.originalFilename ?: return ResponseEntity.badRequest().body("No filename provided")
        val userId = "user456" // Would come from authentication
        
        // ok: kotlin-lack-of-file-extension-validation
        val extension = fileName.substringAfterLast('.', "").toLowerCase()
        val allowedMediaTypes = setOf("mp4", "mp3", "wav", "avi", "mov")
        
        if (extension !in allowedMediaTypes) {
            return ResponseEntity.badRequest().body("Unsupported media format")
        }
        
        val safeFileName = "${UUID.randomUUID()}.$extension"
        val mediaPath = "/media/$userId/$safeFileName"
        val targetFile = File(mediaPath)
        targetFile.parentFile.mkdirs()
        file.transferTo(targetFile)
        
        return ResponseEntity.ok("Media uploaded as $safeFileName")
    }
    
    @PostMapping("/secure-temp-upload")
    fun good_case_12(@RequestParam("file") file: MultipartFile): ResponseEntity<String> {
        val originalName = file.originalFilename ?: return ResponseEntity.badRequest().body("No filename provided")
        
        // ok: kotlin-lack-of-file-extension-validation
        val extension = originalName.substringAfterLast('.', "").toLowerCase()
        if (!listOf("csv", "txt", "json", "xml").contains(extension)) {
            return ResponseEntity.badRequest().body("Only data files are allowed")
        }
        
        val tempFileName = "temp_${UUID.randomUUID()}.$extension"
        val tempFile = File(System.getProperty("java.io.tmpdir"), tempFileName)
        file.transferTo(tempFile)
        
        return ResponseEntity.ok("File uploaded to temp directory as $tempFileName")
    }
    
    @PostMapping("/secure-process-csv")
    fun good_case_13(@RequestParam("csvFile") file: MultipartFile): ResponseEntity<String> {
        val fileName = file.originalFilename ?: return ResponseEntity.badRequest().body("No filename provided")
        
        // ok: kotlin-lack-of-file-extension-validation
        val extension = fileName.substringAfterLast('.', "").toLowerCase()
        if (extension != "csv") {
            return ResponseEntity.badRequest().body("Only CSV files are allowed")
        }
        
        val safeFileName = "import_${System.currentTimeMillis()}.csv"
        val csvFile = File("/data/imports/$safeFileName")
        file.transferTo(csvFile)
        
        // Process CSV file...
        return ResponseEntity.ok("CSV processing started for $safeFileName")
    }
    
    @PostMapping("/secure-save-base64")
    fun good_case_14(@RequestParam("base64Data") base64Data: String, @RequestParam("fileName") fileName: String): ResponseEntity<String> {
        // ok: kotlin-lack-of-file-extension-validation
        val extension = fileName.substringAfterLast('.', "").toLowerCase()
        val allowedExtensions = setOf("jpg", "png", "pdf", "txt")
        
        if (extension !in allowedExtensions) {
            return ResponseEntity.badRequest().body("Unsupported file type")
        }
        
        val safeFileName = "${UUID.randomUUID()}.$extension"
        val decodedData = java.util.Base64.getDecoder().decode(base64Data)
        val outputFile = File("/uploads/$safeFileName")
        outputFile.writeBytes(decodedData)
        
        return ResponseEntity.ok("Base64 data saved as $safeFileName")
    }
    
    @PostMapping("/secure-upload-with-content-check")
    fun good_case_15(@RequestParam("file") file: MultipartFile): ResponseEntity<String> {
        val fileName = file.originalFilename ?: return ResponseEntity.badRequest().body("No filename provided")
        
        // ok: kotlin-lack-of-file-extension-validation
        val extension = fileName.substringAfterLast('.', "").toLowerCase()
        
        // First check extension
        if (extension !in listOf("jpg", "jpeg", "png", "gif")) {
            return ResponseEntity.badRequest().body("Only image files are allowed")
        }
        
        // Additional content-type verification
        val contentType = file.contentType
        if (contentType == null || !contentType.startsWith("image/")) {
            return ResponseEntity.badRequest().body("Content is not an image")
        }
        
        val safeFileName = "${UUID.randomUUID()}.$extension"
        val targetFile = File("/secure-storage/$safeFileName")
        file.transferTo(targetFile)
        
        return ResponseEntity.ok("Image verified and uploaded as $safeFileName")
    }
}