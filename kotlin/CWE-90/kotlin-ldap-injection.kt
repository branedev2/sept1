import javax.naming.Context
import javax.naming.directory.InitialDirContext
import javax.naming.directory.SearchControls
import javax.naming.directory.DirContext
import javax.naming.NamingEnumeration
import javax.naming.directory.SearchResult
import javax.naming.NamingException
import java.util.Hashtable
import java.util.Properties
import io.ktor.application.*
import io.ktor.request.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.server.engine.*
import io.ktor.http.*
import io.ktor.features.*
import org.springframework.web.bind.annotation.*
import org.springframework.stereotype.Controller
import org.springframework.http.ResponseEntity
import jakarta.servlet.http.HttpServletRequest
import org.apache.directory.ldap.client.api.LdapConnection
import org.apache.directory.ldap.client.api.LdapNetworkConnection
import org.apache.directory.api.ldap.model.message.SearchRequest
import org.apache.directory.api.ldap.model.message.SearchRequestImpl
import org.apache.directory.api.ldap.model.name.Dn
import org.apache.directory.api.ldap.model.filter.FilterParser
import org.apache.directory.api.ldap.model.filter.EqualityNode
import org.apache.directory.api.ldap.model.entry.DefaultEntry
import org.apache.directory.api.ldap.model.entry.Entry
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException
import org.apache.directory.api.ldap.model.exception.LdapException

// True Positive Examples (Vulnerable Code)

// {fact rule=ldap-injection@v1.0 defects=1}
@Controller
fun bad_case_1(request: HttpServletRequest) {
    val username = request.getParameter("username")
    
    val env = Hashtable<String, String>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://localhost:389/dc=example,dc=com"
    
    val ctx = InitialDirContext(env)
    val searchControls = SearchControls()
    searchControls.searchScope = SearchControls.SUBTREE_SCOPE
    
    // ruleid: kotlin-ldap-injection
    val results = ctx.search("ou=users", "(uid=$username)", searchControls)
    
    while (results.hasMore()) {
        val result = results.next() as SearchResult
        println(result.nameInNamespace)
    }
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
@RestController
fun bad_case_2(@RequestParam username: String) {
    val env = Hashtable<String, String>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://localhost:389/dc=example,dc=com"
    env[Context.SECURITY_AUTHENTICATION] = "simple"
    env[Context.SECURITY_PRINCIPAL] = "cn=admin,dc=example,dc=com"
    env[Context.SECURITY_CREDENTIALS] = "admin_password"
    
    val ctx = InitialDirContext(env)
    
    // ruleid: kotlin-ldap-injection
    val filter = "(|(uid=$username)(cn=$username))"
    val results = ctx.search("ou=users", filter, null)
    
    // Process results
}
// {/fact}

fun Application.bad_case_3() {
    routing {
        get("/search") {
            val query = call.request.queryParameters["query"] ?: ""
            
            val env = Hashtable<String, String>()
            env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
            env[Context.PROVIDER_URL] = "ldap://localhost:389"
            
            val ctx = InitialDirContext(env)
            val searchControls = SearchControls()
            
            // ruleid: kotlin-ldap-injection
            val results = ctx.search("dc=example,dc=com", "(objectClass=$query)", searchControls)
            
            val users = mutableListOf<String>()
            while (results.hasMore()) {
                val result = results.next() as SearchResult
                users.add(result.nameInNamespace)
            }
            
            call.respond(users)
        }
    }
}

// {fact rule=ldap-injection@v1.0 defects=1}
@Controller
fun bad_case_4() {
    @GetMapping("/ldap/search")
    fun searchUser(request: HttpServletRequest): ResponseEntity<List<String>> {
        val firstName = request.getParameter("firstName")
        val lastName = request.getParameter("lastName")
        
        val env = Hashtable<String, String>()
        env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
        env[Context.PROVIDER_URL] = "ldap://localhost:389"
        
        val ctx = InitialDirContext(env)
        val searchControls = SearchControls()
        
        // ruleid: kotlin-ldap-injection
        val filter = "(&(givenName=$firstName)(sn=$lastName))"
        val results = ctx.search("ou=people,dc=example,dc=com", filter, searchControls)
        
        val users = mutableListOf<String>()
        while (results.hasMore()) {
            users.add((results.next() as SearchResult).nameInNamespace)
        }
        
        return ResponseEntity.ok(users)
    }
}
// {/fact}

fun Application.bad_case_5() {
    routing {
        post("/authenticate") {
            val formParameters = call.receiveParameters()
            val username = formParameters["username"] ?: ""
            val password = formParameters["password"] ?: ""
            
            val env = Hashtable<String, String>()
            env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
            env[Context.PROVIDER_URL] = "ldap://localhost:389"
            
            val ctx = InitialDirContext(env)
            
            // ruleid: kotlin-ldap-injection
            val searchFilter = "(&(uid=$username)(userPassword=$password))"
            val results = ctx.search("dc=example,dc=com", searchFilter, null)
            
            if (results.hasMore()) {
                call.respond(HttpStatusCode.OK, "Authentication successful")
            } else {
                call.respond(HttpStatusCode.Unauthorized, "Authentication failed")
            }
        }
    }
}

// {fact rule=ldap-injection@v1.0 defects=1}
@Controller
fun bad_case_6() {
    @GetMapping("/ldap/group")
    fun getGroupMembers(request: HttpServletRequest): List<String> {
        val groupName = request.getParameter("group")
        
        val env = Hashtable<String, String>()
        env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
        env[Context.PROVIDER_URL] = "ldap://localhost:389"
        
        val ctx = InitialDirContext(env)
        
        // ruleid: kotlin-ldap-injection
        val baseDn = "ou=$groupName,dc=example,dc=com"
        val results = ctx.search(baseDn, "(objectClass=person)", null)
        
        val members = mutableListOf<String>()
        while (results.hasMore()) {
            members.add((results.next() as SearchResult).nameInNamespace)
        }
        
        return members
    }
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
fun bad_case_7() {
    val connection = LdapNetworkConnection("localhost", 389)
    connection.bind("cn=admin,dc=example,dc=com", "admin_password")
    
    fun searchUser(request: HttpServletRequest) {
        val username = request.getParameter("username")
        
        // ruleid: kotlin-ldap-injection
        val searchRequest = SearchRequestImpl()
        searchRequest.base = Dn("dc=example,dc=com")
        searchRequest.filter = FilterParser.parse("(uid=$username)")
        
        val response = connection.search(searchRequest)
        
        response.forEach { entry ->
            println(entry.dn)
        }
    }
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
@RestController
fun bad_case_8() {
    @GetMapping("/user/search")
    fun searchUser(@RequestParam email: String): List<String> {
        val connection = LdapNetworkConnection("localhost", 389)
        connection.bind("cn=admin,dc=example,dc=com", "admin_password")
        
        // ruleid: kotlin-ldap-injection
        val filter = "(mail=$email)"
        val response = connection.search("dc=example,dc=com", filter, SearchScope.SUBTREE)
        
        val results = mutableListOf<String>()
        response.forEach { entry ->
            results.add(entry.dn.toString())
        }
        
        return results
    }
}
// {/fact}

fun Application.bad_case_9() {
    routing {
        get("/directory") {
            val role = call.request.queryParameters["role"] ?: ""
            
            val env = Hashtable<String, String>()
            env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
            env[Context.PROVIDER_URL] = "ldap://localhost:389"
            
            val ctx = InitialDirContext(env)
            val searchControls = SearchControls()
            searchControls.searchScope = SearchControls.SUBTREE_SCOPE
            
            // ruleid: kotlin-ldap-injection
            val results = ctx.search("dc=example,dc=com", "(title=$role)", searchControls)
            
            val employees = mutableListOf<String>()
            while (results.hasMore()) {
                employees.add((results.next() as SearchResult).nameInNamespace)
            }
            
            call.respond(employees)
        }
    }
}

// {fact rule=ldap-injection@v1.0 defects=1}
@Controller
fun bad_case_10() {
    @PostMapping("/user/find")
    fun findUserByAttribute(request: HttpServletRequest): ResponseEntity<List<String>> {
        val attributeName = request.getParameter("attribute")
        val attributeValue = request.getParameter("value")
        
        val env = Hashtable<String, String>()
        env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
        env[Context.PROVIDER_URL] = "ldap://localhost:389"
        
        val ctx = InitialDirContext(env)
        
        // ruleid: kotlin-ldap-injection
        val filter = "($attributeName=$attributeValue)"
        val results = ctx.search("dc=example,dc=com", filter, null)
        
        val users = mutableListOf<String>()
        while (results.hasMore()) {
            users.add((results.next() as SearchResult).nameInNamespace)
        }
        
        return ResponseEntity.ok(users)
    }
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
fun bad_case_11() {
    fun searchEmployees(request: HttpServletRequest) {
        val department = request.getParameter("department")
        val manager = request.getParameter("manager")
        
        val env = Hashtable<String, String>()
        env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
        env[Context.PROVIDER_URL] = "ldap://localhost:389"
        
        val ctx = InitialDirContext(env)
        
        // ruleid: kotlin-ldap-injection
        val filter = "(&(department=$department)(manager=cn=$manager,dc=example,dc=com))"
        val results = ctx.search("ou=employees,dc=example,dc=com", filter, null)
        
        while (results.hasMore()) {
            println((results.next() as SearchResult).nameInNamespace)
        }
    }
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
@RestController
fun bad_case_12() {
    @GetMapping("/ldap/attribute")
    fun getUsersByAttribute(@RequestParam attribute: String, @RequestParam value: String): List<Map<String, Any>> {
        val connection = LdapNetworkConnection("localhost", 389)
        connection.bind("cn=admin,dc=example,dc=com", "admin_password")
        
        // ruleid: kotlin-ldap-injection
        val searchRequest = SearchRequestImpl()
        searchRequest.base = Dn("dc=example,dc=com")
        searchRequest.filter = FilterParser.parse("($attribute=$value)")
        
        val response = connection.search(searchRequest)
        
        val results = mutableListOf<Map<String, Any>>()
        response.forEach { entry ->
            val userMap = mutableMapOf<String, Any>()
            userMap["dn"] = entry.dn.toString()
            entry.attributes.forEach { attribute ->
                userMap[attribute.id] = attribute.getString()
            }
            results.add(userMap)
        }
        
        return results
    }
}
// {/fact}

fun Application.bad_case_13() {
    routing {
        get("/ldap/search/complex") {
            val name = call.request.queryParameters["name"] ?: ""
            val email = call.request.queryParameters["email"] ?: ""
            
            val env = Hashtable<String, String>()
            env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
            env[Context.PROVIDER_URL] = "ldap://localhost:389"
            
            val ctx = InitialDirContext(env)
            
            // ruleid: kotlin-ldap-injection
            val filter = "(&(|(cn=*$name*)(sn=*$name*))(mail=*$email*))"
            val results = ctx.search("dc=example,dc=com", filter, null)
            
            val users = mutableListOf<String>()
            while (results.hasMore()) {
                users.add((results.next() as SearchResult).nameInNamespace)
            }
            
            call.respond(users)
        }
    }
}

// {fact rule=ldap-injection@v1.0 defects=1}
@Controller
fun bad_case_14() {
    @GetMapping("/ldap/search/wildcard")
    fun searchWithWildcard(request: HttpServletRequest): List<String> {
        val searchTerm = request.getParameter("term")
        
        val env = Hashtable<String, String>()
        env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
        env[Context.PROVIDER_URL] = "ldap://localhost:389"
        
        val ctx = InitialDirContext(env)
        val searchControls = SearchControls()
        searchControls.searchScope = SearchControls.SUBTREE_SCOPE
        
        // ruleid: kotlin-ldap-injection
        val filter = "(|(cn=*$searchTerm*)(sn=*$searchTerm*)(mail=*$searchTerm*))"
        val results = ctx.search("dc=example,dc=com", filter, searchControls)
        
        val users = mutableListOf<String>()
        while (results.hasMore()) {
            users.add((results.next() as SearchResult).nameInNamespace)
        }
        
        return users
    }
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
fun bad_case_15() {
    fun searchUserByDN(request: HttpServletRequest) {
        val userDN = request.getParameter("dn")
        
        val env = Hashtable<String, String>()
        env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
        env[Context.PROVIDER_URL] = "ldap://localhost:389"
        
        val ctx = InitialDirContext(env)
        
        try {
            // ruleid: kotlin-ldap-injection
            val attributes = ctx.getAttributes(userDN)
            attributes.all.asIterator().forEach { attribute ->
                println("${attribute.id}: ${attribute.get()}")
            }
        } catch (e: NamingException) {
            println("Error: ${e.message}")
        }
    }
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=ldap-injection@v1.0 defects=0}
@Controller
fun good_case_1(request: HttpServletRequest) {
    val username = request.getParameter("username")
    
    // Sanitize input by escaping special characters
    val sanitizedUsername = username.replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
        .replace("*", "\\*")
        .replace("/", "\\/")
    
    val env = Hashtable<String, String>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://localhost:389/dc=example,dc=com"
    
    val ctx = InitialDirContext(env)
    val searchControls = SearchControls()
    searchControls.searchScope = SearchControls.SUBTREE_SCOPE
    
    // ok: kotlin-ldap-injection
    val results = ctx.search("ou=users", "(uid=$sanitizedUsername)", searchControls)
    
    while (results.hasMore()) {
        val result = results.next() as SearchResult
        println(result.nameInNamespace)
    }
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
@RestController
fun good_case_2(@RequestParam username: String) {
    // Validate input using regex to ensure it only contains alphanumeric characters
    if (!username.matches(Regex("^[a-zA-Z0-9]+$"))) {
        throw IllegalArgumentException("Username contains invalid characters")
    }
    
    val env = Hashtable<String, String>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://localhost:389/dc=example,dc=com"
    env[Context.SECURITY_AUTHENTICATION] = "simple"
    env[Context.SECURITY_PRINCIPAL] = "cn=admin,dc=example,dc=com"
    env[Context.SECURITY_CREDENTIALS] = "admin_password"
    
    val ctx = InitialDirContext(env)
    
    // ok: kotlin-ldap-injection
    val filter = "(|(uid=$username)(cn=$username))"
    val results = ctx.search("ou=users", filter, null)
    
    // Process results
}
// {/fact}

fun Application.good_case_3() {
    routing {
        get("/search") {
            val query = call.request.queryParameters["query"] ?: ""
            
            // Use a whitelist of allowed values
            val allowedQueries = setOf("person", "organizationalUnit", "organization")
            if (!allowedQueries.contains(query)) {
                call.respond(HttpStatusCode.BadRequest, "Invalid query parameter")
                return@get
            }
            
            val env = Hashtable<String, String>()
            env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
            env[Context.PROVIDER_URL] = "ldap://localhost:389"
            
            val ctx = InitialDirContext(env)
            val searchControls = SearchControls()
            
            // ok: kotlin-ldap-injection
            val results = ctx.search("dc=example,dc=com", "(objectClass=$query)", searchControls)
            
            val users = mutableListOf<String>()
            while (results.hasMore()) {
                val result = results.next() as SearchResult
                users.add(result.nameInNamespace)
            }
            
            call.respond(users)
        }
    }
}

// {fact rule=ldap-injection@v1.0 defects=0}
@Controller
fun good_case_4() {
    @GetMapping("/ldap/search")
    fun searchUser(request: HttpServletRequest): ResponseEntity<List<String>> {
        val firstName = request.getParameter("firstName") ?: ""
        val lastName = request.getParameter("lastName") ?: ""
        
        // Sanitize inputs
        val sanitizedFirstName = sanitizeLdapInput(firstName)
        val sanitizedLastName = sanitizeLdapInput(lastName)
        
        val env = Hashtable<String, String>()
        env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
        env[Context.PROVIDER_URL] = "ldap://localhost:389"
        
        val ctx = InitialDirContext(env)
        val searchControls = SearchControls()
        
        // ok: kotlin-ldap-injection
        val filter = "(&(givenName=$sanitizedFirstName)(sn=$sanitizedLastName))"
        val results = ctx.search("ou=people,dc=example,dc=com", filter, searchControls)
        
        val users = mutableListOf<String>()
        while (results.hasMore()) {
            users.add((results.next() as SearchResult).nameInNamespace)
        }
        
        return ResponseEntity.ok(users)
    }
    
    private fun sanitizeLdapInput(input: String): String {
        return input.replace("\\", "\\\\")
            .replace("*", "\\*")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .replace("/", "\\/")
    }
}
// {/fact}

fun Application.good_case_5() {
    routing {
        post("/authenticate") {
            val formParameters = call.receiveParameters()
            val username = formParameters["username"] ?: ""
            val password = formParameters["password"] ?: ""
            
            // Use parameterized LDAP authentication instead of constructing a filter
            val env = Hashtable<String, String>()
            env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
            env[Context.PROVIDER_URL] = "ldap://localhost:389"
            
            try {
                // ok: kotlin-ldap-injection
                // Use direct bind authentication instead of searching with credentials in filter
                env[Context.SECURITY_AUTHENTICATION] = "simple"
                env[Context.SECURITY_PRINCIPAL] = "uid=$username,ou=users,dc=example,dc=com"
                env[Context.SECURITY_CREDENTIALS] = password
                
                val ctx = InitialDirContext(env)
                ctx.close()
                call.respond(HttpStatusCode.OK, "Authentication successful")
            } catch (e: NamingException) {
                call.respond(HttpStatusCode.Unauthorized, "Authentication failed")
            }
        }
    }
}

// {fact rule=ldap-injection@v1.0 defects=0}
@Controller
fun good_case_6() {
    @GetMapping("/ldap/group")
    fun getGroupMembers(request: HttpServletRequest): List<String> {
        val groupName = request.getParameter("group")
        
        // Validate group name against a whitelist
        val validGroups = setOf("admins", "users", "developers", "testers")
        if (!validGroups.contains(groupName)) {
            throw IllegalArgumentException("Invalid group name")
        }
        
        val env = Hashtable<String, String>()
        env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
        env[Context.PROVIDER_URL] = "ldap://localhost:389"
        
        val ctx = InitialDirContext(env)
        
        // ok: kotlin-ldap-injection
        val baseDn = "ou=$groupName,dc=example,dc=com"
        val results = ctx.search(baseDn, "(objectClass=person)", null)
        
        val members = mutableListOf<String>()
        while (results.hasMore()) {
            members.add((results.next() as SearchResult).nameInNamespace)
        }
        
        return members
    }
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
fun good_case_7() {
    val connection = LdapNetworkConnection("localhost", 389)
    connection.bind("cn=admin,dc=example,dc=com", "admin_password")
    
    fun searchUser(request: HttpServletRequest) {
        val username = request.getParameter("username")
        
        // Sanitize the input
        val sanitizedUsername = username.replace("\\", "\\\\")
            .replace("*", "\\*")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .replace("/", "\\/")
        
        // ok: kotlin-ldap-injection
        val searchRequest = SearchRequestImpl()
        searchRequest.base = Dn("dc=example,dc=com")
        searchRequest.filter = FilterParser.parse("(uid=$sanitizedUsername)")
        
        val response = connection.search(searchRequest)
        
        response.forEach { entry ->
            println(entry.dn)
        }
    }
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
@RestController
fun good_case_8() {
    @GetMapping("/user/search")
    fun searchUser(@RequestParam email: String): List<String> {
        // Validate email format
        if (!email.matches(Regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$"))) {
            throw IllegalArgumentException("Invalid email format")
        }
        
        val connection = LdapNetworkConnection("localhost", 389)
        connection.bind("cn=admin,dc=example,dc=com", "admin_password")
        
        // ok: kotlin-ldap-injection
        val sanitizedEmail = email.replace("\\", "\\\\")
            .replace("*", "\\*")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .replace("/", "\\/")
        
        val filter = "(mail=$sanitizedEmail)"
        val response = connection.search("dc=example,dc=com", filter, SearchScope.SUBTREE)
        
        val results = mutableListOf<String>()
        response.forEach { entry ->
            results.add(entry.dn.toString())
        }
        
        return results
    }
}
// {/fact}

fun Application.good_case_9() {
    routing {
        get("/directory") {
            val role = call.request.queryParameters["role"] ?: ""
            
            // Use a prepared list of allowed roles
            val allowedRoles = setOf("developer", "manager", "admin", "tester")
            if (!allowedRoles.contains(role)) {
                call.respond(HttpStatusCode.BadRequest, "Invalid role")
                return@get
            }
            
            val env = Hashtable<String, String>()
            env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
            env[Context.PROVIDER_URL] = "ldap://localhost:389"
            
            val ctx = InitialDirContext(env)
            val searchControls = SearchControls()
            searchControls.searchScope = SearchControls.SUBTREE_SCOPE
            
            // ok: kotlin-ldap-injection
            val results = ctx.search("dc=example,dc=com", "(title=$role)", searchControls)
            
            val employees = mutableListOf<String>()
            while (results.hasMore()) {
                employees.add((results.next() as SearchResult).nameInNamespace)
            }
            
            call.respond(employees)
        }
    }
}

// {fact rule=ldap-injection@v1.0 defects=0}
@Controller
fun good_case_10() {
    @PostMapping("/user/find")
    fun findUserByAttribute(request: HttpServletRequest): ResponseEntity<List<String>> {
        val attributeName = request.getParameter("attribute")
        val attributeValue = request.getParameter("value")
        
        // Whitelist allowed attributes
        val allowedAttributes = setOf("cn", "sn", "mail", "uid", "employeeNumber")
        if (!allowedAttributes.contains(attributeName)) {
            return ResponseEntity.badRequest().body(listOf("Invalid attribute name"))
        }
        
        // Sanitize attribute value
        val sanitizedValue = attributeValue.replace("\\", "\\\\")
            .replace("*", "\\*")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .replace("/", "\\/")
        
        val env = Hashtable<String, String>()
        env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
        env[Context.PROVIDER_URL] = "ldap://localhost:389"
        
        val ctx = InitialDirContext(env)
        
        // ok: kotlin-ldap-injection
        val filter = "($attributeName=$sanitizedValue)"
        val results = ctx.search("dc=example,dc=com", filter, null)
        
        val users = mutableListOf<String>()
        while (results.hasMore()) {
            users.add((results.next() as SearchResult).nameInNamespace)
        }
        
        return ResponseEntity.ok(users)
    }
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
fun good_case_11() {
    fun searchEmployees(request: HttpServletRequest) {
        val department = request.getParameter("department")
        val manager = request.getParameter("manager")
        
        // Sanitize inputs
        val sanitizedDept = department.replace("\\", "\\\\")
            .replace("*", "\\*")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .replace("/", "\\/")
        
        val sanitizedManager = manager.replace("\\", "\\\\")
            .replace("*", "\\*")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .replace("/", "\\/")
        
        val env = Hashtable<String, String>()
        env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
        env[Context.PROVIDER_URL] = "ldap://localhost:389"
        
        val ctx = InitialDirContext(env)
        
        // ok: kotlin-ldap-injection
        val filter = "(&(department=$sanitizedDept)(manager=cn=$sanitizedManager,dc=example,dc=com))"
        val results = ctx.search("ou=employees,dc=example,dc=com", filter, null)
        
        while (results.hasMore()) {
            println((results.next() as SearchResult).nameInNamespace)
        }
    }
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
@RestController
fun good_case_12() {
    @GetMapping("/ldap/attribute")
    fun getUsersByAttribute(@RequestParam attribute: String, @RequestParam value: String): List<Map<String, Any>> {
        // Whitelist allowed attributes
        val allowedAttributes = setOf("cn", "sn", "givenName", "mail", "uid")
        if (!allowedAttributes.contains(attribute)) {
            throw IllegalArgumentException("Invalid attribute name")
        }
        
        // Sanitize the value
        val sanitizedValue = value.replace("\\", "\\\\")
            .replace("*", "\\*")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .replace("/", "\\/")
        
        val connection = LdapNetworkConnection("localhost", 389)
        connection.bind("cn=admin,dc=example,dc=com", "admin_password")
        
        // ok: kotlin-ldap-injection
        val searchRequest = SearchRequestImpl()
        searchRequest.base = Dn("dc=example,dc=com")
        searchRequest.filter = FilterParser.parse("($attribute=$sanitizedValue)")
        
        val response = connection.search(searchRequest)
        
        val results = mutableListOf<Map<String, Any>>()
        response.forEach { entry ->
            val userMap = mutableMapOf<String, Any>()
            userMap["dn"] = entry.dn.toString()
            entry.attributes.forEach { attribute ->
                userMap[attribute.id] = attribute.getString()
            }
            results.add(userMap)
        }
        
        return results
    }
}
// {/fact}

fun Application.good_case_13() {
    routing {
        get("/ldap/search/complex") {
            val name = call.request.queryParameters["name"] ?: ""
            val email = call.request.queryParameters["email"] ?: ""
            
            // Sanitize inputs
            val sanitizedName = name.replace("\\", "\\\\")
                .replace("*", "\\*")
                .replace("(", "\\(")
                .replace(")", "\\)")
                .replace("/", "\\/")
            
            val sanitizedEmail = email.replace("\\", "\\\\")
                .replace("*", "\\*")
                .replace("(", "\\(")
                .replace(")", "\\)")
                .replace("/", "\\/")
            
            val env = Hashtable<String, String>()
            env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
            env[Context.PROVIDER_URL] = "ldap://localhost:389"
            
            val ctx = InitialDirContext(env)
            
            // ok: kotlin-ldap-injection
            val filter = "(&(|(cn=*$sanitizedName*)(sn=*$sanitizedName*))(mail=*$sanitizedEmail*))"
            val results = ctx.search("dc=example,dc=com", filter, null)
            
            val users = mutableListOf<String>()
            while (results.hasMore()) {
                users.add((results.next() as SearchResult).nameInNamespace)
            }
            
            call.respond(users)
        }
    }
}

// {fact rule=ldap-injection@v1.0 defects=0}
@Controller
fun good_case_14() {
    @GetMapping("/ldap/search/wildcard")
    fun searchWithWildcard(request: HttpServletRequest): List<String> {
        val searchTerm = request.getParameter("term") ?: ""
        
        // Validate input - only allow alphanumeric and some safe characters
        if (!searchTerm.matches(Regex("^[a-zA-Z0-9 .@_-]+$"))) {
            throw IllegalArgumentException("Search term contains invalid characters")
        }
        
        val env = Hashtable<String, String>()
        env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
        env[Context.PROVIDER_URL] = "ldap://localhost:389"
        
        val ctx = InitialDirContext(env)
        val searchControls = SearchControls()
        searchControls.searchScope = SearchControls.SUBTREE_SCOPE
        
        // ok: kotlin-ldap-injection
        val filter = "(|(cn=*$searchTerm*)(sn=*$searchTerm*)(mail=*$searchTerm*))"
        val results = ctx.search("dc=example,dc=com", filter, searchControls)
        
        val users = mutableListOf<String>()
        while (results.hasMore()) {
            users.add((results.next() as SearchResult).nameInNamespace)
        }
        
        return users
    }
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
fun good_case_15() {
    fun searchUserByDN(request: HttpServletRequest) {
        val userDN = request.getParameter("dn")
        
        try {
            // Validate DN format using LDAP API
            val dn = Dn(userDN)
            if (!dn.isValid()) {
                throw IllegalArgumentException("Invalid DN format")
            }
            
            val env = Hashtable<String, String>()
            env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
            env[Context.PROVIDER_URL] = "ldap://localhost:389"
            
            val ctx = InitialDirContext(env)
            
            // ok: kotlin-ldap-injection
            val attributes = ctx.getAttributes(userDN)
            attributes.all.asIterator().forEach { attribute ->
                println("${attribute.id}: ${attribute.get()}")
            }
        } catch (e: LdapInvalidDnException) {
            println("Invalid DN format: ${e.message}")
        } catch (e: NamingException) {
            println("Error: ${e.message}")
        }
    }
}
// {/fact}