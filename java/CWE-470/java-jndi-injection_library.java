import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;
import java.util.Properties;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;
import org.apache.commons.text.StringEscapeUtils;
import org.owasp.encoder.Encode;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.tomcat.util.descriptor.web.ContextResource;
import org.apache.catalina.Context;
import org.apache.naming.ContextBindings;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import org.springframework.jdbc.datasource.lookup.JndiDataSourceLookup;
import org.springframework.jndi.JndiTemplate;
import org.springframework.jndi.JndiObjectFactoryBean;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.UrlValidator;
import java.util.regex.Pattern;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.HttpEntity;
import org.apache.http.util.EntityUtils;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.Filter;
import org.apache.shiro.jndi.JndiCallback;
import org.apache.shiro.jndi.JndiTemplate;
import org.glassfish.jersey.client.JerseyClient;
import org.glassfish.jersey.client.JerseyClientBuilder;
import org.glassfish.jersey.client.JerseyWebTarget;
import java.io.IOException;

// Security Issue: JNDI Injection Vulnerability

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) throws NamingException {
    String userInput = request.getParameter("jndiName");
    Context ctx = new InitialContext();
    
    // ruleid: java-jndi-injection
    Object obj = ctx.lookup(userInput);
    
    System.out.println("Found object: " + obj);
}

public void bad_case_2(HttpServletRequest request) throws NamingException {
    String userInput = request.getParameter("ldapUrl");
    Hashtable<String, String> env = new Hashtable<>();
    env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
    
    // ruleid: java-jndi-injection
    env.put(Context.PROVIDER_URL, userInput);
    
    DirContext ctx = new InitialDirContext(env);
    ctx.search("ou=users", "(uid=admin)", null);
}

@RestController
public class JndiSpringController {
// {fact rule=unsafe-reflection@v1.0 defects=1}
    public void bad_case_3(@RequestParam String jndiName) {
        try {
            JndiTemplate jndiTemplate = new JndiTemplate();
            
            // ruleid: java-jndi-injection
            Object dataSource = jndiTemplate.lookup(jndiName);
            
            System.out.println("Found: " + dataSource);
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }
}
// {/fact}

public void bad_case_4(HttpServletRequest request) {
    try {
        String userInput = request.getHeader("X-JNDI-Resource");
        JndiObjectFactoryBean factory = new JndiObjectFactoryBean();
        
        // ruleid: java-jndi-injection
        factory.setJndiName(userInput);
        
        factory.afterPropertiesSet();
        Object obj = factory.getObject();
        System.out.println("Retrieved: " + obj);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5(HttpServletRequest request) {
    try {
        String userInput = request.getParameter("dsName");
        JndiDataSourceLookup dsLookup = new JndiDataSourceLookup();
        
        // ruleid: java-jndi-injection
        DataSource dataSource = dsLookup.getDataSource(userInput);
        
        Connection conn = dataSource.getConnection();
        System.out.println("Connected to: " + conn.getMetaData().getURL());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_6(HttpServletRequest request) {
    try {
        String userInput = request.getParameter("ldapName");
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl("ldap://localhost:389");
        contextSource.afterPropertiesSet();
        LdapTemplate ldapTemplate = new LdapTemplate(contextSource);
        
        // ruleid: java-jndi-injection
        ldapTemplate.lookup(userInput);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7(HttpServletRequest request) {
    try {
        String userInput = request.getParameter("ldapUrl");
        LdapConnectionConfig config = new LdapConnectionConfig();
        
        // ruleid: java-jndi-injection
        config.setLdapHost(userInput);
        
        config.setLdapPort(389);
        LdapConnection connection = new LdapNetworkConnection(config);
        connection.bind("cn=admin,dc=example,dc=com", "password");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8(HttpServletRequest request) {
    try {
        String userInput = request.getParameter("resourceName");
        ContextResource resource = new ContextResource();
        resource.setName("jdbc/TestDB");
        resource.setAuth("Container");
        resource.setType("javax.sql.DataSource");
        
        // ruleid: java-jndi-injection
        resource.setProperty("jndiName", userInput);
        
        // Add resource to context
        Context ctx = (Context) new InitialContext().lookup("java:comp/env");
        ctx.bind("jdbc/TestDB", resource);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9(HttpServletRequest request) {
    try {
        String userInput = request.getParameter("jndiCallback");
        org.apache.shiro.jndi.JndiTemplate template = new org.apache.shiro.jndi.JndiTemplate();
        
        // ruleid: java-jndi-injection
        template.execute(userInput, new JndiCallback<Object>() {
            public Object doInContext(javax.naming.Context context) throws NamingException {
                return context.lookup("");
            }
        });
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10(HttpServletRequest request) {
    try {
        String userInput = request.getParameter("ldapFilter");
        LDAPConnection connection = new LDAPConnection("localhost", 389, "cn=admin,dc=example,dc=com", "password");
        
        // ruleid: java-jndi-injection
        SearchRequest searchRequest = new SearchRequest("dc=example,dc=com", 
                                                      SearchScope.SUB, 
                                                      Filter.create(userInput));
        
        connection.search(searchRequest);
    } catch (LDAPException e) {
        e.printStackTrace();
    }
}

public void bad_case_11(HttpServletRequest request) {
    try {
        String userInput = request.getParameter("jndiName");
        Properties env = new Properties();
        env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.rmi.registry.RegistryContextFactory");
        env.put(Context.PROVIDER_URL, "rmi://localhost:1099");
        Context ctx = new InitialContext(env);
        
        // ruleid: java-jndi-injection
        Object obj = ctx.lookupLink(userInput);
        
        System.out.println("Found object: " + obj);
    } catch (NamingException e) {
        e.printStackTrace();
    }
}

public void bad_case_12(HttpServletRequest request) {
    try {
        String userInput = request.getParameter("jndiName");
        Context ctx = new InitialContext();
        
        // ruleid: java-jndi-injection
        ctx.rebind(userInput, new String("test"));
        
    } catch (NamingException e) {
        e.printStackTrace();
    }
}

public void bad_case_13(HttpServletRequest request) {
    try {
        String userInput = request.getParameter("jndiName");
        Context ctx = new InitialContext();
        
        // ruleid: java-jndi-injection
        ctx.bind(userInput, new String("test"));
        
    } catch (NamingException e) {
        e.printStackTrace();
    }
}

public void bad_case_14(HttpServletRequest request) {
    try {
        String userInput = request.getParameter("jndiName");
        Context ctx = new InitialContext();
        
        // ruleid: java-jndi-injection
        ctx.rename(userInput, "newName");
        
    } catch (NamingException e) {
        e.printStackTrace();
    }
}

public void bad_case_15(HttpServletRequest request) {
    try {
        String userInput = request.getParameter("jndiName");
        Context ctx = new InitialContext();
        
        // ruleid: java-jndi-injection
        ctx.list(userInput);
        
    } catch (NamingException e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) throws NamingException {
    String userInput = request.getParameter("jndiName");
    
    // Validate input against a whitelist of allowed JNDI names
    String[] allowedNames = {"java:comp/env/jdbc/myDB", "java:comp/env/mail/Session"};
    boolean isValid = false;
    
    for (String allowed : allowedNames) {
        if (allowed.equals(userInput)) {
            isValid = true;
            break;
        }
    }
    
    if (isValid) {
        Context ctx = new InitialContext();
        // ok: java-jndi-injection
        Object obj = ctx.lookup(userInput);
        System.out.println("Found object: " + obj);
    } else {
        throw new SecurityException("Invalid JNDI name requested");
    }
}

public void good_case_2(HttpServletRequest request) throws NamingException {
    // Use hardcoded LDAP URL instead of user input
    Hashtable<String, String> env = new Hashtable<>();
    env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
    
    // ok: java-jndi-injection
    env.put(Context.PROVIDER_URL, "ldap://localhost:389");
    
    DirContext ctx = new InitialDirContext(env);
    
    // Safely use user input in search filter with proper escaping
    String userInput = request.getParameter("username");
    String escapedInput = StringEscapeUtils.escapeJava(userInput);
    ctx.search("ou=users", "(uid=" + escapedInput + ")", null);
}

@RestController
public class SafeJndiSpringController {
// {fact rule=unsafe-reflection@v1.0 defects=0}
    public void good_case_3(@RequestParam String resourceType) {
        try {
            JndiTemplate jndiTemplate = new JndiTemplate();
            
            // Map user input to predefined JNDI names
            String jndiName;
            switch (resourceType) {
                case "datasource":
                    jndiName = "java:comp/env/jdbc/myDataSource";
                    break;
                case "mail":
                    jndiName = "java:comp/env/mail/Session";
                    break;
                default:
                    throw new IllegalArgumentException("Invalid resource type");
            }
            
            // ok: java-jndi-injection
            Object resource = jndiTemplate.lookup(jndiName);
            
            System.out.println("Found: " + resource);
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }
}
// {/fact}

public void good_case_4(HttpServletRequest request) {
    try {
        // Use constant JNDI name instead of user input
        JndiObjectFactoryBean factory = new JndiObjectFactoryBean();
        
        // ok: java-jndi-injection
        factory.setJndiName("java:comp/env/jdbc/myDataSource");
        
        factory.afterPropertiesSet();
        Object obj = factory.getObject();
        System.out.println("Retrieved: " + obj);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5(HttpServletRequest request) {
    try {
        // Map user input to predefined datasource names
        String userInput = request.getParameter("dsType");
        String dsName;
        
        if ("customers".equals(userInput)) {
            dsName = "java:comp/env/jdbc/customersDB";
        } else if ("inventory".equals(userInput)) {
            dsName = "java:comp/env/jdbc/inventoryDB";
        } else {
            dsName = "java:comp/env/jdbc/defaultDB";
        }
        
        JndiDataSourceLookup dsLookup = new JndiDataSourceLookup();
        
        // ok: java-jndi-injection
        DataSource dataSource = dsLookup.getDataSource(dsName);
        
        Connection conn = dataSource.getConnection();
        System.out.println("Connected to: " + conn.getMetaData().getURL());
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_6(HttpServletRequest request) {
    try {
        // Use a predefined set of LDAP paths
        String userInput = request.getParameter("ldapEntity");
        String ldapName;
        
        if ("users".equals(userInput)) {
            ldapName = "ou=users,dc=example,dc=com";
        } else if ("groups".equals(userInput)) {
            ldapName = "ou=groups,dc=example,dc=com";
        } else {
            throw new IllegalArgumentException("Invalid LDAP entity");
        }
        
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl("ldap://localhost:389");
        contextSource.afterPropertiesSet();
        LdapTemplate ldapTemplate = new LdapTemplate(contextSource);
        
        // ok: java-jndi-injection
        ldapTemplate.lookup(ldapName);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7(HttpServletRequest request) {
    try {
        // Use hardcoded LDAP host instead of user input
        LdapConnectionConfig config = new LdapConnectionConfig();
        
        // ok: java-jndi-injection
        config.setLdapHost("ldap.example.com");
        
        config.setLdapPort(389);
        LdapConnection connection = new LdapNetworkConnection(config);
        
        // Safely handle user input for authentication
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        // Validate username format before using
        if (username != null && username.matches("^[a-zA-Z0-9._-]{3,50}$")) {
            String dn = "cn=" + username + ",dc=example,dc=com";
            connection.bind(dn, password);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8(HttpServletRequest request) {
    try {
        // Use constant resource name instead of user input
        ContextResource resource = new ContextResource();
        resource.setName("jdbc/TestDB");
        resource.setAuth("Container");
        resource.setType("javax.sql.DataSource");
        
        // ok: java-jndi-injection
        resource.setProperty("jndiName", "java:comp/env/jdbc/fixedDataSource");
        
        // Add resource to context
        Context ctx = (Context) new InitialContext().lookup("java:comp/env");
        ctx.bind("jdbc/TestDB", resource);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9(HttpServletRequest request) {
    try {
        // Use constant JNDI path instead of user input
        org.apache.shiro.jndi.JndiTemplate template = new org.apache.shiro.jndi.JndiTemplate();
        
        // ok: java-jndi-injection
        template.execute("java:comp/env/ejb/MyBean", new JndiCallback<Object>() {
            public Object doInContext(javax.naming.Context context) throws NamingException {
                return context.lookup("");
            }
        });
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10(HttpServletRequest request) {
    try {
        String userInput = request.getParameter("username");
        
        // Validate and sanitize the input
        if (userInput == null || !userInput.matches("^[a-zA-Z0-9._-]{3,50}$")) {
            throw new IllegalArgumentException("Invalid username format");
        }
        
        LDAPConnection connection = new LDAPConnection("localhost", 389, 
                                                     "cn=admin,dc=example,dc=com", "password");
        
        // Safely construct LDAP filter with sanitized input
        // ok: java-jndi-injection
        SearchRequest searchRequest = new SearchRequest("dc=example,dc=com", 
                                                      SearchScope.SUB, 
                                                      Filter.createEqualityFilter("uid", userInput));
        
        connection.search(searchRequest);
    } catch (LDAPException e) {
        e.printStackTrace();
    }
}

public void good_case_11(HttpServletRequest request) {
    try {
        // Use predefined JNDI names based on user selection
        String userSelection = request.getParameter("resourceType");
        String jndiName;
        
        if ("printer".equals(userSelection)) {
            jndiName = "rmi://localhost:1099/Printer";
        } else if ("calculator".equals(userSelection)) {
            jndiName = "rmi://localhost:1099/Calculator";
        } else {
            throw new IllegalArgumentException("Invalid resource type");
        }
        
        Properties env = new Properties();
        env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.rmi.registry.RegistryContextFactory");
        env.put(Context.PROVIDER_URL, "rmi://localhost:1099");
        Context ctx = new InitialContext(env);
        
        // ok: java-jndi-injection
        Object obj = ctx.lookupLink(jndiName);
        
        System.out.println("Found object: " + obj);
    } catch (NamingException e) {
        e.printStackTrace();
    }
}

public void good_case_12(HttpServletRequest request) {
    try {
        // Use constant JNDI name instead of user input
        Context ctx = new InitialContext();
        
        // ok: java-jndi-injection
        ctx.rebind("java:comp/env/myString", new String("test"));
        
    } catch (NamingException e) {
        e.printStackTrace();
    }
}

public void good_case_13(HttpServletRequest request) {
    try {
        // Use constant JNDI name instead of user input
        Context ctx = new InitialContext();
        
        // ok: java-jndi-injection
        ctx.bind("java:comp/env/myObject", new String("test"));
        
    } catch (NamingException e) {
        e.printStackTrace();
    }
}

public void good_case_14(HttpServletRequest request) {
    try {
        // Use constant JNDI names instead of user input
        Context ctx = new InitialContext();
        
        // ok: java-jndi-injection
        ctx.rename("java:comp/env/oldName", "java:comp/env/newName");
        
    } catch (NamingException e) {
        e.printStackTrace();
    }
}

public void good_case_15(HttpServletRequest request) {
    try {
        // Use constant JNDI context instead of user input
        Context ctx = new InitialContext();
        
        // ok: java-jndi-injection
        ctx.list("java:comp/env");
        
    } catch (NamingException e) {
        e.printStackTrace();
    }
}