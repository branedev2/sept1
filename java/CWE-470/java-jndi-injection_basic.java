import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;
import java.util.Properties;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import java.io.IOException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import java.util.Base64;
import org.apache.commons.text.StringEscapeUtils;
import org.owasp.encoder.Encode;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class JndiInjectionExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=unsafe-reflection@v1.0 defects=1}
    @WebServlet("/bad1")
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("ldapUrl");
            Context ctx = new InitialContext();
            // ruleid: java-jndi-injection
            Object obj = ctx.lookup(userInput);
            response.getWriter().println("JNDI lookup result: " + obj);
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/bad2")
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getHeader("X-LDAP-Lookup");
            Context ctx = new InitialContext();
            // ruleid: java-jndi-injection
            Object obj = ctx.lookup("ldap://" + userInput);
            response.getWriter().println("JNDI lookup result: " + obj);
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/bad3")
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("jndiName");
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            DirContext ctx = new InitialDirContext(env);
            // ruleid: java-jndi-injection
            Object obj = ctx.lookup(userInput);
            response.getWriter().println("JNDI lookup result: " + obj);
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/bad4")
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("jndiPath");
            Context ctx = new InitialContext();
            String lookupString = "java:comp/env/" + userInput;
            // ruleid: java-jndi-injection
            Object obj = ctx.lookup(lookupString);
            response.getWriter().println("JNDI lookup result: " + obj);
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/bad5")
    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("ldapServer");
            String ldapUrl = "ldap://" + userInput + ":389/dc=example,dc=com";
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, ldapUrl);
            // ruleid: java-jndi-injection
            DirContext ctx = new InitialDirContext(env);
            response.getWriter().println("LDAP connection established");
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/bad6")
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("jndiName");
            if (userInput != null && !userInput.isEmpty()) {
                Context ctx = new InitialContext();
                // ruleid: java-jndi-injection
                ctx.lookupLink(userInput);
                response.getWriter().println("JNDI lookup completed");
            }
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/bad7")
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("jndiName");
            String prefix = "java:comp/env/";
            String lookupString = prefix + userInput;
            Context ctx = new InitialContext();
            // ruleid: java-jndi-injection
            Object obj = ctx.lookupLink(lookupString);
            response.getWriter().println("JNDI lookup result: " + obj);
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/bad8")
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("ldapBase");
            Properties env = new Properties();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            DirContext ctx = new InitialDirContext(env);
            // ruleid: java-jndi-injection
            Object obj = ctx.search(userInput, "(objectClass=*)", null);
            response.getWriter().println("LDAP search completed");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/bad9")
    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("jndiUrl");
            Context ctx = new InitialContext();
            // ruleid: java-jndi-injection
            Object obj = ctx.lookup("rmi://" + userInput);
            response.getWriter().println("JNDI lookup result: " + obj);
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/bad10")
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("ldapFilter");
            Properties env = new Properties();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            DirContext ctx = new InitialDirContext(env);
            // ruleid: java-jndi-injection
            Object obj = ctx.search("dc=example,dc=com", userInput, null);
            response.getWriter().println("LDAP search completed");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/bad11")
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("jndiName");
            Context ctx = new InitialContext();
            String lookupString = "";
            if (userInput.startsWith("ldap://")) {
                lookupString = userInput;
            } else {
                lookupString = "java:comp/env/" + userInput;
            }
            // ruleid: java-jndi-injection
            Object obj = ctx.lookup(lookupString);
            response.getWriter().println("JNDI lookup result: " + obj);
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/bad12")
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("jndiName");
            Context ctx = new InitialContext();
            if (userInput.length() > 10) {
                userInput = userInput.substring(0, 10);
            }
            // ruleid: java-jndi-injection
            Object obj = ctx.lookup(userInput);
            response.getWriter().println("JNDI lookup result: " + obj);
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/bad13")
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("jndiName");
            Context ctx = new InitialContext();
            String lookupString = userInput.replace("../", "");
            // ruleid: java-jndi-injection
            Object obj = ctx.lookup(lookupString);
            response.getWriter().println("JNDI lookup result: " + obj);
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/bad14")
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("jndiName");
            Context ctx = new InitialContext();
            // Basic attempt at sanitization, but still vulnerable
            String lookupString = userInput.replaceAll("ldap://", "");
            // ruleid: java-jndi-injection
            Object obj = ctx.lookup("ldap://" + lookupString);
            response.getWriter().println("JNDI lookup result: " + obj);
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/bad15")
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("jndiName");
            Context ctx = new InitialContext();
            // Encoding doesn't prevent JNDI injection
            String encodedInput = Base64.getEncoder().encodeToString(userInput.getBytes());
            String decodedInput = new String(Base64.getDecoder().decode(encodedInput));
            // ruleid: java-jndi-injection
            Object obj = ctx.lookup(decodedInput);
            response.getWriter().println("JNDI lookup result: " + obj);
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    // True Negative Examples (Safe Code)

    @WebServlet("/good1")
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("jndiName");
            // ok: java-jndi-injection
            // Using a whitelist of allowed JNDI names
            String[] allowedNames = {"java:comp/env/jdbc/myDB", "java:comp/env/mail/Session", "java:comp/env/cfg/AppConfig"};
            boolean isAllowed = false;
            for (String allowed : allowedNames) {
                if (allowed.equals(userInput)) {
                    isAllowed = true;
                    break;
                }
            }
            
            if (isAllowed) {
                Context ctx = new InitialContext();
                Object obj = ctx.lookup(userInput);
                response.getWriter().println("JNDI lookup result: " + obj);
            } else {
                response.getWriter().println("Invalid JNDI name requested");
            }
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/good2")
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            // ok: java-jndi-injection
            // Using hardcoded JNDI name, not user input
            String jndiName = "java:comp/env/jdbc/myDataSource";
            Context ctx = new InitialContext();
            Object obj = ctx.lookup(jndiName);
            response.getWriter().println("JNDI lookup result: " + obj);
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/good3")
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("dbName");
            // ok: java-jndi-injection
            // Validate input against a strict pattern before using in JNDI
            Pattern pattern = Pattern.compile("^[a-zA-Z0-9_-]{1,20}$");
            Matcher matcher = pattern.matcher(userInput);
            
            if (matcher.matches()) {
                Context ctx = new InitialContext();
                Object obj = ctx.lookup("java:comp/env/jdbc/" + userInput);
                response.getWriter().println("JNDI lookup result: " + obj);
            } else {
                response.getWriter().println("Invalid database name format");
            }
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/good4")
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            // ok: java-jndi-injection
            // Using configuration from a secure source, not user input
            String jndiName = System.getProperty("app.jndi.name", "java:comp/env/default");
            Context ctx = new InitialContext();
            Object obj = ctx.lookup(jndiName);
            response.getWriter().println("JNDI lookup result: " + obj);
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/good5")
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("resourceType");
            // ok: java-jndi-injection
            // Using a switch statement to map user input to safe, predefined values
            String jndiName;
            switch (userInput) {
                case "db":
                    jndiName = "java:comp/env/jdbc/myDB";
                    break;
                case "mail":
                    jndiName = "java:comp/env/mail/Session";
                    break;
                case "config":
                    jndiName = "java:comp/env/cfg/AppConfig";
                    break;
                default:
                    jndiName = "java:comp/env/default";
            }
            
            Context ctx = new InitialContext();
            Object obj = ctx.lookup(jndiName);
            response.getWriter().println("JNDI lookup result: " + obj);
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/good6")
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            // ok: java-jndi-injection
            // Using a constant for LDAP URL, not user input
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://ldap.example.com:389");
            DirContext ctx = new InitialDirContext(env);
            Object obj = ctx.search("dc=example,dc=com", "(objectClass=person)", null);
            response.getWriter().println("LDAP search completed");
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/good7")
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("resourceId");
            // ok: java-jndi-injection
            // Validate input is numeric before using in a predefined JNDI pattern
            if (userInput != null && userInput.matches("^[0-9]+$")) {
                Context ctx = new InitialContext();
                Object obj = ctx.lookup("java:comp/env/resource/" + userInput);
                response.getWriter().println("JNDI lookup result: " + obj);
            } else {
                response.getWriter().println("Invalid resource ID format");
            }
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/good8")
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            // ok: java-jndi-injection
            // Using environment variables for JNDI configuration, not user input
            String ldapUrl = System.getenv("LDAP_URL");
            if (ldapUrl == null || ldapUrl.isEmpty()) {
                ldapUrl = "ldap://default.example.com:389";
            }
            
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, ldapUrl);
            DirContext ctx = new InitialDirContext(env);
            response.getWriter().println("LDAP connection established");
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/good9")
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("ldapFilter");
            // ok: java-jndi-injection
            // Properly escaping LDAP filter input
            String escapedFilter = StringEscapeUtils.escapeJava(userInput);
            
            Properties env = new Properties();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            DirContext ctx = new InitialDirContext(env);
            Object obj = ctx.search("dc=example,dc=com", "(cn=" + escapedFilter + ")", null);
            response.getWriter().println("LDAP search completed");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/good10")
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            // ok: java-jndi-injection
            // Using a predefined enum to map to JNDI resources
            String resourceType = request.getParameter("type");
            JndiResource resource = JndiResource.fromString(resourceType);
            
            Context ctx = new InitialContext();
            Object obj = ctx.lookup(resource.getJndiName());
            response.getWriter().println("JNDI lookup result: " + obj);
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/good11")
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("ldapName");
            // ok: java-jndi-injection
            // Using OWASP Encoder to properly encode user input for LDAP
            String encodedInput = Encode.forLdap(userInput);
            
            Properties env = new Properties();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            DirContext ctx = new InitialDirContext(env);
            Object obj = ctx.search("dc=example,dc=com", "(cn=" + encodedInput + ")", null);
            response.getWriter().println("LDAP search completed");
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/good12")
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            // ok: java-jndi-injection
            // Using application configuration for JNDI names
            Properties appConfig = new Properties();
            appConfig.load(JndiInjectionExamples.class.getResourceAsStream("/app.properties"));
            String jndiName = appConfig.getProperty("jndi.datasource.name");
            
            Context ctx = new InitialContext();
            Object obj = ctx.lookup(jndiName);
            response.getWriter().println("JNDI lookup result: " + obj);
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/good13")
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String userInput = request.getParameter("resourceName");
            // ok: java-jndi-injection
            // Validating input against a strict allowlist and using a prefix
            String[] allowedResources = {"users", "groups", "roles", "permissions"};
            boolean isAllowed = false;
            
            for (String resource : allowedResources) {
                if (resource.equals(userInput)) {
                    isAllowed = true;
                    break;
                }
            }
            
            if (isAllowed) {
                Context ctx = new InitialContext();
                Object obj = ctx.lookup("java:comp/env/security/" + userInput);
                response.getWriter().println("JNDI lookup result: " + obj);
            } else {
                response.getWriter().println("Invalid resource name");
            }
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/good14")
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            // ok: java-jndi-injection
            // Using a configuration map to safely map user input to JNDI names
            String userInput = request.getParameter("service");
            
            // Map of allowed service names to their JNDI paths
            java.util.Map<String, String> serviceMap = new java.util.HashMap<>();
            serviceMap.put("email", "java:comp/env/mail/Session");
            serviceMap.put("database", "java:comp/env/jdbc/DataSource");
            serviceMap.put("queue", "java:comp/env/jms/Queue");
            
            String jndiPath = serviceMap.get(userInput);
            if (jndiPath != null) {
                Context ctx = new InitialContext();
                Object obj = ctx.lookup(jndiPath);
                response.getWriter().println("JNDI lookup result: " + obj);
            } else {
                response.getWriter().println("Unknown service requested");
            }
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    @WebServlet("/good15")
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            // ok: java-jndi-injection
            // Using a factory method to create safe JNDI names
            String resourceType = request.getParameter("type");
            String resourceName = request.getParameter("name");
            
            String jndiName = getSafeJndiName(resourceType, resourceName);
            if (jndiName != null) {
                Context ctx = new InitialContext();
                Object obj = ctx.lookup(jndiName);
                response.getWriter().println("JNDI lookup result: " + obj);
            } else {
                response.getWriter().println("Invalid resource type or name");
            }
        } catch (NamingException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }

    // Helper enum for good_case_10
    private enum JndiResource {
        DATABASE("java:comp/env/jdbc/myDB"),
        MAIL("java:comp/env/mail/Session"),
        CONFIG("java:comp/env/cfg/AppConfig"),
        DEFAULT("java:comp/env/default");
        
        private final String jndiName;
        
        JndiResource(String jndiName) {
            this.jndiName = jndiName;
        }
        
        public String getJndiName() {
            return jndiName;
        }
        
        public static JndiResource fromString(String text) {
            if (text != null) {
                for (JndiResource resource : JndiResource.values()) {
                    if (text.equalsIgnoreCase(resource.name())) {
                        return resource;
                    }
                }
            }
            return DEFAULT;
        }
    }
    
    // Helper method for good_case_15
    private String getSafeJndiName(String resourceType, String resourceName) {
        // Validate resource type
        if (resourceType == null || !resourceType.matches("^(db|mail|jms|config)$")) {
            return null;
        }
        
        // Validate resource name
        if (resourceName == null || !resourceName.matches("^[a-zA-Z0-9_-]{1,20}$")) {
            return null;
        }
        
        // Create safe JNDI name based on validated inputs
        switch (resourceType) {
            case "db":
                return "java:comp/env/jdbc/" + resourceName;
            case "mail":
                return "java:comp/env/mail/" + resourceName;
            case "jms":
                return "java:comp/env/jms/" + resourceName;
            case "config":
                return "java:comp/env/cfg/" + resourceName;
            default:
                return null;
        }
    }
}
// {/fact}