import io.ktor.application.*
import io.ktor.http.*
import io.ktor.request.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import org.apache.commons.text.StringEscapeUtils
import org.jsoup.Jsoup
import org.jsoup.safety.Whitelist
import org.owasp.encoder.Encode
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.*
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

// True Positives (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
@Controller
fun bad_case_1(request: HttpServletRequest, response: HttpServletResponse) {
    val userInput = request.getParameter("comment")
    response.writer.write("<div>User comment: $userInput</div>")
    // ruleid: kotlin-cross-site-scripting
    response.writer.flush()
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
@Controller
fun bad_case_2(request: HttpServletRequest, response: HttpServletResponse) {
    val username = request.getParameter("username")
    val html = """
        <html>
            <body>
                <h1>Welcome, $username!</h1>
            </body>
        </html>
    """
    // ruleid: kotlin-cross-site-scripting
    response.writer.write(html)
}
// {/fact}

@RestController
class BadController1 {
    @GetMapping("/profile")
    fun bad_case_3(@RequestParam("bio") bio: String, model: Model): String {
        // ruleid: kotlin-cross-site-scripting
        return "<div class='bio-section'>$bio</div>"
    }
}

@Controller
class BadController2 {
// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/message")
    fun bad_case_4(request: HttpServletRequest, response: HttpServletResponse) {
        val message = request.getParameter("message")
        val script = request.getParameter("script")
        
        response.contentType = "text/html"
        // ruleid: kotlin-cross-site-scripting
        response.writer.println("<p>Your message: $message</p><script>$script</script>")
    }
// {/fact}
}

fun Application.bad_case_5() {
    routing {
        get("/search") {
            val query = call.request.queryParameters["q"] ?: ""
            val html = "<h2>Search results for: $query</h2>"
            // ruleid: kotlin-cross-site-scripting
            call.respondText(html, ContentType.Text.Html)
        }
    }
}

@Controller
class BadController3 {
    @GetMapping("/user/{id}")
    fun bad_case_6(@PathVariable id: String, @RequestParam("name") name: String, response: HttpServletResponse) {
        val userData = "<div id='user-$id'>Name: $name</div>"
        response.contentType = "text/html"
        // ruleid: kotlin-cross-site-scripting
        response.writer.write(userData)
    }
}

fun Application.bad_case_7() {
    routing {
        post("/comment") {
            val formParameters = call.receiveParameters()
            val comment = formParameters["comment"] ?: ""
            val author = formParameters["author"] ?: "Anonymous"
            
            val html = """
                <div class="comment">
                    <h3>$author said:</h3>
                    <p>$comment</p>
                </div>
            """
            // ruleid: kotlin-cross-site-scripting
            call.respondText(html, ContentType.Text.Html)
        }
    }
}

// {fact rule=autoescape-disabled@v1.0 defects=1}
@Controller
fun bad_case_8(request: HttpServletRequest, response: HttpServletResponse) {
    val searchTerm = request.getParameter("q")
    val category = request.getParameter("category")
    
    val html = StringBuilder()
    html.append("<h1>Search Results</h1>")
    html.append("<p>Category: $category</p>")
    html.append("<p>You searched for: $searchTerm</p>")
    
    // ruleid: kotlin-cross-site-scripting
    response.writer.write(html.toString())
}
// {/fact}

@RestController
class BadController4 {
    @GetMapping("/preview")
    fun bad_case_9(@RequestParam("html") userHtml: String): String {
        // ruleid: kotlin-cross-site-scripting
        return "<div class='preview-container'>$userHtml</div>"
    }
}

fun Application.bad_case_10() {
    routing {
        get("/error") {
            val errorMessage = call.request.queryParameters["message"] ?: "Unknown error"
            val errorCode = call.request.queryParameters["code"] ?: "500"
            
            val html = """
                <div class="error-box">
                    <h2>Error $errorCode</h2>
                    <p>$errorMessage</p>
                </div>
            """
            // ruleid: kotlin-cross-site-scripting
            call.respondText(html, ContentType.Text.Html)
        }
    }
}

@Controller
class BadController5 {
// {fact rule=autoescape-disabled@v1.0 defects=1}
    @PostMapping("/feedback")
    fun bad_case_11(request: HttpServletRequest, response: HttpServletResponse) {
        val feedback = request.getParameter("feedback")
        val email = request.getParameter("email")
        
        val html = """
            <div class="feedback-received">
                <h2>Thank you for your feedback!</h2>
                <p>We will contact you at: $email</p>
                <div class="feedback-content">$feedback</div>
            </div>
        """
        // ruleid: kotlin-cross-site-scripting
        response.writer.write(html)
    }
// {/fact}
}

fun Application.bad_case_12() {
    routing {
        get("/welcome") {
            val firstName = call.request.queryParameters["firstName"] ?: ""
            val lastName = call.request.queryParameters["lastName"] ?: ""
            
            val html = """
                <html>
                    <body>
                        <h1>Welcome to our site, $firstName $lastName!</h1>
                        <p>We're glad you're here.</p>
                    </body>
                </html>
            """
            // ruleid: kotlin-cross-site-scripting
            call.respondText(html, ContentType.Text.Html)
        }
    }
}

@RestController
class BadController6 {
    @GetMapping("/embed")
    fun bad_case_13(@RequestParam("code") embedCode: String): String {
        // ruleid: kotlin-cross-site-scripting
        return """
            <div class="embed-container">
                $embedCode
            </div>
        """
    }
}

// {fact rule=autoescape-disabled@v1.0 defects=1}
@Controller
fun bad_case_14(request: HttpServletRequest, response: HttpServletResponse) {
    val title = request.getParameter("title")
    val content = request.getParameter("content")
    
    response.contentType = "text/html"
    // ruleid: kotlin-cross-site-scripting
    response.writer.write("""
        <article>
            <h1>$title</h1>
            <div class="content">$content</div>
        </article>
    """)
}
// {/fact}

fun Application.bad_case_15() {
    routing {
        post("/profile/update") {
            val formParameters = call.receiveParameters()
            val bio = formParameters["bio"] ?: ""
            val interests = formParameters["interests"] ?: ""
            
            val html = """
                <div class="profile-updated">
                    <h2>Profile Updated</h2>
                    <div class="bio">$bio</div>
                    <div class="interests">$interests</div>
                </div>
            """
            // ruleid: kotlin-cross-site-scripting
            call.respondText(html, ContentType.Text.Html)
        }
    }
}

// True Negatives (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
@Controller
fun good_case_1(request: HttpServletRequest, response: HttpServletResponse) {
    val userInput = request.getParameter("comment")
    val safeInput = StringEscapeUtils.escapeHtml4(userInput)
    // ok: kotlin-cross-site-scripting
    response.writer.write("<div>User comment: $safeInput</div>")
    response.writer.flush()
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
@Controller
fun good_case_2(request: HttpServletRequest, response: HttpServletResponse) {
    val username = request.getParameter("username")
    val safeUsername = Encode.forHtml(username)
    val html = """
        <html>
            <body>
                <h1>Welcome, $safeUsername!</h1>
            </body>
        </html>
    """
    // ok: kotlin-cross-site-scripting
    response.writer.write(html)
}
// {/fact}

@RestController
class GoodController1 {
    @GetMapping("/profile")
    fun good_case_3(@RequestParam("bio") bio: String, model: Model): String {
        val safeBio = Jsoup.clean(bio, Whitelist.basic())
        // ok: kotlin-cross-site-scripting
        return "<div class='bio-section'>$safeBio</div>"
    }
}

@Controller
class GoodController2 {
// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/message")
    fun good_case_4(request: HttpServletRequest, response: HttpServletResponse) {
        val message = request.getParameter("message")
        val script = request.getParameter("script")
        
        val safeMessage = StringEscapeUtils.escapeHtml4(message)
        val safeScript = StringEscapeUtils.escapeHtml4(script)
        
        response.contentType = "text/html"
        // ok: kotlin-cross-site-scripting
        response.writer.println("<p>Your message: $safeMessage</p><script>$safeScript</script>")
    }
// {/fact}
}

fun Application.good_case_5() {
    routing {
        get("/search") {
            val query = call.request.queryParameters["q"] ?: ""
            val safeQuery = Encode.forHtml(query)
            val html = "<h2>Search results for: $safeQuery</h2>"
            // ok: kotlin-cross-site-scripting
            call.respondText(html, ContentType.Text.Html)
        }
    }
}

@Controller
class GoodController3 {
    @GetMapping("/user/{id}")
    fun good_case_6(@PathVariable id: String, @RequestParam("name") name: String, response: HttpServletResponse) {
        val safeId = StringEscapeUtils.escapeHtml4(id)
        val safeName = StringEscapeUtils.escapeHtml4(name)
        val userData = "<div id='user-$safeId'>Name: $safeName</div>"
        response.contentType = "text/html"
        // ok: kotlin-cross-site-scripting
        response.writer.write(userData)
    }
}

fun Application.good_case_7() {
    routing {
        post("/comment") {
            val formParameters = call.receiveParameters()
            val comment = formParameters["comment"] ?: ""
            val author = formParameters["author"] ?: "Anonymous"
            
            val safeComment = Jsoup.clean(comment, Whitelist.basic())
            val safeAuthor = Encode.forHtml(author)
            
            val html = """
                <div class="comment">
                    <h3>$safeAuthor said:</h3>
                    <p>$safeComment</p>
                </div>
            """
            // ok: kotlin-cross-site-scripting
            call.respondText(html, ContentType.Text.Html)
        }
    }
}

// {fact rule=autoescape-disabled@v1.0 defects=0}
@Controller
fun good_case_8(request: HttpServletRequest, response: HttpServletResponse) {
    val searchTerm = request.getParameter("q")
    val category = request.getParameter("category")
    
    val safeSearchTerm = StringEscapeUtils.escapeHtml4(searchTerm)
    val safeCategory = StringEscapeUtils.escapeHtml4(category)
    
    val html = StringBuilder()
    html.append("<h1>Search Results</h1>")
    html.append("<p>Category: $safeCategory</p>")
    html.append("<p>You searched for: $safeSearchTerm</p>")
    
    // ok: kotlin-cross-site-scripting
    response.writer.write(html.toString())
}
// {/fact}

@RestController
class GoodController4 {
    @GetMapping("/preview")
    fun good_case_9(@RequestParam("html") userHtml: String): String {
        val safeHtml = Jsoup.clean(userHtml, Whitelist.relaxed())
        // ok: kotlin-cross-site-scripting
        return "<div class='preview-container'>$safeHtml</div>"
    }
}

fun Application.good_case_10() {
    routing {
        get("/error") {
            val errorMessage = call.request.queryParameters["message"] ?: "Unknown error"
            val errorCode = call.request.queryParameters["code"] ?: "500"
            
            val safeMessage = Encode.forHtml(errorMessage)
            val safeCode = Encode.forHtml(errorCode)
            
            val html = """
                <div class="error-box">
                    <h2>Error $safeCode</h2>
                    <p>$safeMessage</p>
                </div>
            """
            // ok: kotlin-cross-site-scripting
            call.respondText(html, ContentType.Text.Html)
        }
    }
}

@Controller
class GoodController5 {
// {fact rule=autoescape-disabled@v1.0 defects=0}
    @PostMapping("/feedback")
    fun good_case_11(request: HttpServletRequest, response: HttpServletResponse) {
        val feedback = request.getParameter("feedback")
        val email = request.getParameter("email")
        
        val safeFeedback = Jsoup.clean(feedback, Whitelist.basic())
        val safeEmail = StringEscapeUtils.escapeHtml4(email)
        
        val html = """
            <div class="feedback-received">
                <h2>Thank you for your feedback!</h2>
                <p>We will contact you at: $safeEmail</p>
                <div class="feedback-content">$safeFeedback</div>
            </div>
        """
        // ok: kotlin-cross-site-scripting
        response.writer.write(html)
    }
// {/fact}
}

fun Application.good_case_12() {
    routing {
        get("/welcome") {
            val firstName = call.request.queryParameters["firstName"] ?: ""
            val lastName = call.request.queryParameters["lastName"] ?: ""
            
            val safeFirstName = Encode.forHtml(firstName)
            val safeLastName = Encode.forHtml(lastName)
            
            val html = """
                <html>
                    <body>
                        <h1>Welcome to our site, $safeFirstName $safeLastName!</h1>
                        <p>We're glad you're here.</p>
                    </body>
                </html>
            """
            // ok: kotlin-cross-site-scripting
            call.respondText(html, ContentType.Text.Html)
        }
    }
}

@RestController
class GoodController6 {
    @GetMapping("/embed")
    fun good_case_13(@RequestParam("code") embedCode: String): String {
        val safeCode = Jsoup.clean(embedCode, Whitelist.relaxed())
        // ok: kotlin-cross-site-scripting
        return """
            <div class="embed-container">
                $safeCode
            </div>
        """
    }
}

// {fact rule=autoescape-disabled@v1.0 defects=0}
@Controller
fun good_case_14(request: HttpServletRequest, response: HttpServletResponse) {
    val title = request.getParameter("title")
    val content = request.getParameter("content")
    
    val safeTitle = StringEscapeUtils.escapeHtml4(title)
    val safeContent = Jsoup.clean(content, Whitelist.basic())
    
    response.contentType = "text/html"
    // ok: kotlin-cross-site-scripting
    response.writer.write("""
        <article>
            <h1>$safeTitle</h1>
            <div class="content">$safeContent</div>
        </article>
    """)
}
// {/fact}

fun Application.good_case_15() {
    routing {
        post("/profile/update") {
            val formParameters = call.receiveParameters()
            val bio = formParameters["bio"] ?: ""
            val interests = formParameters["interests"] ?: ""
            
            val safeBio = Encode.forHtml(bio)
            val safeInterests = Encode.forHtml(interests)
            
            val html = """
                <div class="profile-updated">
                    <h2>Profile Updated</h2>
                    <div class="bio">$safeBio</div>
                    <div class="interests">$safeInterests</div>
                </div>
            """
            // ok: kotlin-cross-site-scripting
            call.respondText(html, ContentType.Text.Html)
        }
    }
}