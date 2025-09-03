import javax.naming.Context
import javax.naming.directory.InitialDirContext
import java.util.Hashtable
import javax.naming.ldap.InitialLdapContext
import javax.naming.ldap.LdapContext
import java.util.Properties
import javax.naming.directory.DirContext

// True Positives - Vulnerable code examples that should be detected

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_1() {
    val env = Hashtable<String, String>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://localhost:389/dc=example,dc=com"
    // ruleid: kotlin-anonymous-ldap-bind
    env[Context.SECURITY_AUTHENTICATION] = "none"
    
    val ctx = InitialDirContext(env)
    val searchResults = ctx.search("ou=users", "(uid=johndoe)", null)
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_2() {
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://ldapserver:389/o=JNDITutorial"
    // ruleid: kotlin-anonymous-ldap-bind
    env[Context.SECURITY_AUTHENTICATION] = "none"
    env[Context.SECURITY_PRINCIPAL] = ""
    env[Context.SECURITY_CREDENTIALS] = ""
    
    val ctx = InitialDirContext(env)
    ctx.lookup("cn=John Doe")
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_3() {
    val props = Properties()
    props.setProperty(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    props.setProperty(Context.PROVIDER_URL, "ldap://directory.example.com:389")
    // ruleid: kotlin-anonymous-ldap-bind
    props.setProperty(Context.SECURITY_AUTHENTICATION, "none")
    
    val context = InitialDirContext(props)
    val attrs = context.getAttributes("cn=admin,dc=example,dc=com")
    context.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_4() {
    val authType = "none"
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldaps://secure-ldap.example.org:636"
    // ruleid: kotlin-anonymous-ldap-bind
    env[Context.SECURITY_AUTHENTICATION] = authType
    
    val ctx = InitialDirContext(env)
    ctx.search("ou=people", "(objectClass=person)", null)
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_5() {
    val env = Hashtable<String, String>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://ldap.example.com:389/dc=example,dc=com"
    // ruleid: kotlin-anonymous-ldap-bind
    env.put(Context.SECURITY_AUTHENTICATION, "none")
    
    val ctx = InitialLdapContext(env, null)
    ctx.search("", "(objectClass=*)", null)
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_6() {
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://directory.example.com:389"
    // ruleid: kotlin-anonymous-ldap-bind
    env[Context.SECURITY_AUTHENTICATION] = "None" // Case insensitive
    
    val ctx = InitialDirContext(env)
    ctx.lookup("ou=users,dc=example,dc=com")
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_7() {
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://ldap.example.org:389"
    // ruleid: kotlin-anonymous-ldap-bind
    env[Context.SECURITY_AUTHENTICATION] = "NONE" // All caps
    
    val context = InitialDirContext(env)
    context.search("dc=example,dc=org", "(cn=*)", null)
    context.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_8() {
    val authMethod = "none"
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://ldap.company.com:389"
    // ruleid: kotlin-anonymous-ldap-bind
    env[Context.SECURITY_AUTHENTICATION] = authMethod
    
    val ldapContext = InitialLdapContext(env, null)
    ldapContext.getAttributes("cn=users,dc=company,dc=com")
    ldapContext.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_9() {
    val env = Properties()
    env.setProperty(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.setProperty(Context.PROVIDER_URL, "ldap://ldap.example.net:389")
    // ruleid: kotlin-anonymous-ldap-bind
    env.setProperty(Context.SECURITY_AUTHENTICATION, "none")
    
    val ctx = InitialDirContext(env as Hashtable<*, *>)
    ctx.lookup("ou=departments,dc=example,dc=net")
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_10() {
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://ldap.internal:389"
    
    if (true) {
        // ruleid: kotlin-anonymous-ldap-bind
        env[Context.SECURITY_AUTHENTICATION] = "none"
    } else {
        env[Context.SECURITY_AUTHENTICATION] = "simple"
        env[Context.SECURITY_PRINCIPAL] = "cn=admin"
        env[Context.SECURITY_CREDENTIALS] = "password"
    }
    
    val ctx = InitialDirContext(env)
    ctx.search("dc=internal", "(uid=*)", null)
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_11() {
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://directory.example.com:389"
    
    val useAnonymous = true
    if (useAnonymous) {
        // ruleid: kotlin-anonymous-ldap-bind
        env[Context.SECURITY_AUTHENTICATION] = "none"
    }
    
    val ctx = InitialDirContext(env)
    ctx.lookup("ou=groups,dc=example,dc=com")
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_12() {
    val authTypes = listOf("simple", "none", "strong")
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://ldap.example.org:389"
    // ruleid: kotlin-anonymous-ldap-bind
    env[Context.SECURITY_AUTHENTICATION] = authTypes[1] // "none"
    
    val ctx = InitialDirContext(env)
    ctx.search("ou=employees,dc=example,dc=org", "(sn=Smith)", null)
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_13() {
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://ldap.company.net:389"
    
    val config = mapOf("auth" to "none", "timeout" to "5000")
    // ruleid: kotlin-anonymous-ldap-bind
    env[Context.SECURITY_AUTHENTICATION] = config["auth"] as String
    
    val ctx = InitialDirContext(env)
    ctx.getAttributes("cn=directory,dc=company,dc=net")
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_14() {
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://ldap.example.com:389"
    
    val authMethod = StringBuilder().append("no").append("ne").toString()
    // ruleid: kotlin-anonymous-ldap-bind
    env[Context.SECURITY_AUTHENTICATION] = authMethod
    
    val ctx = InitialLdapContext(env, null)
    ctx.lookup("ou=system,dc=example,dc=com")
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
fun bad_case_15() {
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://ldap.internal.net:389"
    
    val securitySettings = mapOf(
        "authentication" to "none",
        "principal" to "",
        "credentials" to ""
    )
    
    // ruleid: kotlin-anonymous-ldap-bind
    env[Context.SECURITY_AUTHENTICATION] = securitySettings["authentication"] as String
    
    val ctx = InitialDirContext(env)
    ctx.search("dc=internal,dc=net", "(objectClass=person)", null)
    ctx.close()
}
// {/fact}

// True Negatives - Secure code examples that should not be detected

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_1() {
    val env = Hashtable<String, String>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://localhost:389/dc=example,dc=com"
    // ok: kotlin-anonymous-ldap-bind
    env[Context.SECURITY_AUTHENTICATION] = "simple"
    env[Context.SECURITY_PRINCIPAL] = "cn=admin,dc=example,dc=com"
    env[Context.SECURITY_CREDENTIALS] = "adminPassword"
    
    val ctx = InitialDirContext(env)
    val searchResults = ctx.search("ou=users", "(uid=johndoe)", null)
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_2() {
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://ldapserver:389/o=JNDITutorial"
    // ok: kotlin-anonymous-ldap-bind
    env[Context.SECURITY_AUTHENTICATION] = "simple"
    env[Context.SECURITY_PRINCIPAL] = "cn=Directory Manager"
    env[Context.SECURITY_CREDENTIALS] = "ldap123"
    
    val ctx = InitialDirContext(env)
    ctx.lookup("cn=John Doe")
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_3() {
    val props = Properties()
    props.setProperty(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    props.setProperty(Context.PROVIDER_URL, "ldap://directory.example.com:389")
    // ok: kotlin-anonymous-ldap-bind
    props.setProperty(Context.SECURITY_AUTHENTICATION, "strong")
    props.setProperty(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system")
    props.setProperty(Context.SECURITY_CREDENTIALS, "secret")
    
    val context = InitialDirContext(props)
    val attrs = context.getAttributes("cn=admin,dc=example,dc=com")
    context.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_4() {
    val authType = "simple"
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldaps://secure-ldap.example.org:636"
    // ok: kotlin-anonymous-ldap-bind
    env[Context.SECURITY_AUTHENTICATION] = authType
    env[Context.SECURITY_PRINCIPAL] = "cn=admin,dc=example,dc=org"
    env[Context.SECURITY_CREDENTIALS] = "adminPass123"
    
    val ctx = InitialDirContext(env)
    ctx.search("ou=people", "(objectClass=person)", null)
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_5() {
    val env = Hashtable<String, String>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://ldap.example.com:389/dc=example,dc=com"
    // ok: kotlin-anonymous-ldap-bind
    env.put(Context.SECURITY_AUTHENTICATION, "DIGEST-MD5")
    env.put(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system")
    env.put(Context.SECURITY_CREDENTIALS, "secret")
    
    val ctx = InitialLdapContext(env, null)
    ctx.search("", "(objectClass=*)", null)
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_6() {
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://directory.example.com:389"
    
    // No authentication method specified - not using anonymous binding
    // ok: kotlin-anonymous-ldap-bind
    env[Context.SECURITY_PRINCIPAL] = "cn=Directory Manager"
    env[Context.SECURITY_CREDENTIALS] = "password"
    
    val ctx = InitialDirContext(env)
    ctx.lookup("ou=users,dc=example,dc=com")
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_7() {
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://ldap.example.org:389"
    // ok: kotlin-anonymous-ldap-bind
    env[Context.SECURITY_AUTHENTICATION] = "CRAM-MD5"
    env[Context.SECURITY_PRINCIPAL] = "uid=admin,ou=admins,dc=example,dc=org"
    env[Context.SECURITY_CREDENTIALS] = "adminPassword"
    
    val context = InitialDirContext(env)
    context.search("dc=example,dc=org", "(cn=*)", null)
    context.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_8() {
    val authMethod = "simple"
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://ldap.company.com:389"
    // ok: kotlin-anonymous-ldap-bind
    env[Context.SECURITY_AUTHENTICATION] = authMethod
    env[Context.SECURITY_PRINCIPAL] = "cn=admin,dc=company,dc=com"
    env[Context.SECURITY_CREDENTIALS] = System.getenv("LDAP_PASSWORD")
    
    val ldapContext = InitialLdapContext(env, null)
    ldapContext.getAttributes("cn=users,dc=company,dc=com")
    ldapContext.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_9() {
    val env = Properties()
    env.setProperty(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.setProperty(Context.PROVIDER_URL, "ldap://ldap.example.net:389")
    // ok: kotlin-anonymous-ldap-bind
    env.setProperty(Context.SECURITY_AUTHENTICATION, "simple")
    env.setProperty(Context.SECURITY_PRINCIPAL, "uid=user,ou=people,dc=example,dc=net")
    env.setProperty(Context.SECURITY_CREDENTIALS, "userPassword")
    
    val ctx = InitialDirContext(env as Hashtable<*, *>)
    ctx.lookup("ou=departments,dc=example,dc=net")
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_10() {
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://ldap.internal:389"
    
    val useAnonymous = false
    if (useAnonymous) {
        env[Context.SECURITY_AUTHENTICATION] = "none"
    } else {
        // ok: kotlin-anonymous-ldap-bind
        env[Context.SECURITY_AUTHENTICATION] = "simple"
        env[Context.SECURITY_PRINCIPAL] = "cn=admin"
        env[Context.SECURITY_CREDENTIALS] = "password"
    }
    
    val ctx = InitialDirContext(env)
    ctx.search("dc=internal", "(uid=*)", null)
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_11() {
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://directory.example.com:389"
    
    // ok: kotlin-anonymous-ldap-bind
    // Using SASL authentication
    env[Context.SECURITY_AUTHENTICATION] = "GSSAPI"
    
    val ctx = InitialDirContext(env)
    ctx.lookup("ou=groups,dc=example,dc=com")
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_12() {
    val authTypes = listOf("simple", "strong", "EXTERNAL")
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://ldap.example.org:389"
    // ok: kotlin-anonymous-ldap-bind
    env[Context.SECURITY_AUTHENTICATION] = authTypes[0] // "simple"
    env[Context.SECURITY_PRINCIPAL] = "uid=user1,ou=users,dc=example,dc=org"
    env[Context.SECURITY_CREDENTIALS] = "userPassword"
    
    val ctx = InitialDirContext(env)
    ctx.search("ou=employees,dc=example,dc=org", "(sn=Smith)", null)
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_13() {
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://ldap.company.net:389"
    
    val config = mapOf("auth" to "simple", "timeout" to "5000")
    // ok: kotlin-anonymous-ldap-bind
    env[Context.SECURITY_AUTHENTICATION] = config["auth"] as String
    env[Context.SECURITY_PRINCIPAL] = "cn=reader,dc=company,dc=net"
    env[Context.SECURITY_CREDENTIALS] = "readerPassword"
    
    val ctx = InitialDirContext(env)
    ctx.getAttributes("cn=directory,dc=company,dc=net")
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_14() {
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://ldap.example.com:389"
    
    // ok: kotlin-anonymous-ldap-bind
    // Not setting SECURITY_AUTHENTICATION at all and using default
    env[Context.SECURITY_PRINCIPAL] = "cn=admin,dc=example,dc=com"
    env[Context.SECURITY_CREDENTIALS] = "adminPassword"
    
    val ctx = InitialLdapContext(env, null)
    ctx.lookup("ou=system,dc=example,dc=com")
    ctx.close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
fun good_case_15() {
    val env = Hashtable<String, Any>()
    env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
    env[Context.PROVIDER_URL] = "ldap://ldap.internal.net:389"
    
    val securitySettings = mapOf(
        "authentication" to "simple",
        "principal" to "cn=ldapadmin,dc=internal,dc=net",
        "credentials" to "securePassword123"
    )
    
    // ok: kotlin-anonymous-ldap-bind
    env[Context.SECURITY_AUTHENTICATION] = securitySettings["authentication"] as String
    env[Context.SECURITY_PRINCIPAL] = securitySettings["principal"] as String
    env[Context.SECURITY_CREDENTIALS] = securitySettings["credentials"] as String
    
    val ctx = InitialDirContext(env)
    ctx.search("dc=internal,dc=net", "(objectClass=person)", null)
    ctx.close()
}
// {/fact}