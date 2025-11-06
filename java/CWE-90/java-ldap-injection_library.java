import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Hashtable;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import org.springframework.web.bind.annotation.*;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.filter.AndFilter;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;

import org.apache.commons.text.StringEscapeUtils;
import org.owasp.encoder.Encode;
import org.apache.commons.lang3.StringUtils;

import spark.Request;
import spark.Response;
import spark.Spark;

import io.javalin.Javalin;
import io.javalin.http.Context;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import ratpack.handling.Context;
import ratpack.handling.Handler;
import ratpack.http.Request;

import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

import org.ldaptive.*;
import org.ldaptive.SearchFilter;

import com.novell.ldap.*;

// Security Issue: LDAP Injection - CWE-90

// True Positive Examples (Vulnerable/Insecure Code)
public class LdapInjectionExamples {

// {fact rule=ldap-injection@v1.0 defects=1}
    public static void bad_case_1(HttpServletRequest request, HttpServletResponse response) {
        try {
            String username = request.getParameter("username");
            
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            
            DirContext ctx = new InitialDirContext(env);
            
            // ruleid: java-ldap-injection
            String searchFilter = "(uid=" + username + ")";
            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", searchFilter, constraints);
            
            // Process results...
            ctx.close();
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_2(org.springframework.web.bind.annotation.RequestParam String user, LdapTemplate ldapTemplate) {
        try {
            // ruleid: java-ldap-injection
            String filter = "(&(objectClass=person)(uid=" + user + "))";
            List<String> result = ldapTemplate.search(
                "dc=example,dc=com",
                filter,
                (AttributesMapper<String>) attrs -> (String) attrs.get("cn").get()
            );
            // Process results...
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_3(spark.Request req, spark.Response res) {
        String userId = req.queryParams("userId");
        
        try {
            LdapConnection connection = new LdapNetworkConnection("localhost", 389);
            connection.bind("cn=admin,dc=example,dc=com", "password");
            
            // ruleid: java-ldap-injection
            String filter = "(uid=" + userId + ")";
            org.apache.directory.api.ldap.model.message.SearchRequest searchRequest = 
                new org.apache.directory.api.ldap.model.message.SearchRequestImpl();
            searchRequest.setBase(new org.apache.directory.api.ldap.model.name.Dn("dc=example,dc=com"));
            searchRequest.setFilter(filter);
            searchRequest.setScope(SearchScope.SUBTREE);
            
            org.apache.directory.api.ldap.model.message.SearchCursor cursor = 
                connection.search(searchRequest);
            
            // Process results...
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_4(io.javalin.http.Context ctx) {
        String email = ctx.queryParam("email");
        
        try {
            LDAPConnection connection = new LDAPConnection("localhost", 389, 
                                                         "cn=admin,dc=example,dc=com", "password");
            
            // ruleid: java-ldap-injection
            com.unboundid.ldap.sdk.SearchRequest searchRequest = 
                new com.unboundid.ldap.sdk.SearchRequest("dc=example,dc=com", 
                                                       com.unboundid.ldap.sdk.SearchScope.SUB, 
                                                       "(mail=" + email + ")");
            
            SearchResult result = connection.search(searchRequest);
            
            // Process results...
            connection.close();
        } catch (LDAPException e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_5(HttpExchange exchange) {
        try {
            String query = exchange.getRequestURI().getQuery();
            String[] params = query.split("&");
            String cn = "";
            
            for (String param : params) {
                if (param.startsWith("cn=")) {
                    cn = param.substring(3);
                    break;
                }
            }
            
            Hashtable<String, Object> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, "cn=admin,dc=example,dc=com");
            env.put(Context.SECURITY_CREDENTIALS, "password");
            
            DirContext ctx = new InitialDirContext(env);
            
            // ruleid: java-ldap-injection
            String searchFilter = "(cn=" + cn + ")";
            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", searchFilter, constraints);
            
            // Process results...
            ctx.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_6(RoutingContext routingContext) {
        String group = routingContext.request().getParam("group");
        
        try {
            Hashtable<String, Object> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            
            DirContext ctx = new InitialDirContext(env);
            
            // ruleid: java-ldap-injection
            String searchFilter = "(&(objectClass=groupOfNames)(cn=" + group + "))";
            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", searchFilter, constraints);
            
            // Process results...
            ctx.close();
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_7(@RequestBody UserRequest userRequest, LdapTemplate ldapTemplate) {
        String username = userRequest.getUsername();
        
        try {
            // ruleid: java-ldap-injection
            String filter = "(sAMAccountName=" + username + ")";
            List<String> result = ldapTemplate.search(
                "dc=example,dc=com",
                filter,
                (AttributesMapper<String>) attrs -> (String) attrs.get("displayName").get()
            );
            // Process results...
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_8(ratpack.handling.Context ctx) {
        String department = ctx.getRequest().getQueryParams().get("department");
        
        try {
            org.ldaptive.ConnectionFactory connectionFactory = 
                new org.ldaptive.DefaultConnectionFactory("ldap://localhost:389");
            Connection connection = connectionFactory.getConnection();
            connection.open();
            
            // ruleid: java-ldap-injection
            org.ldaptive.SearchFilter filter = new org.ldaptive.SearchFilter("(department=" + department + ")");
            org.ldaptive.SearchOperation search = new org.ldaptive.SearchOperation(connection);
            org.ldaptive.SearchRequest request = new org.ldaptive.SearchRequest("dc=example,dc=com", filter);
            
            org.ldaptive.SearchResult result = search.execute(request).getResult();
            
            // Process results...
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_9(HttpServletRequest request) {
        String role = request.getParameter("role");
        
        try {
            LDAPConnection ldapConnection = new LDAPConnection();
            ldapConnection.connect("localhost", 389);
            ldapConnection.bind(3, "cn=admin,dc=example,dc=com", "password".getBytes());
            
            // ruleid: java-ldap-injection
            String filter = "(role=" + role + ")";
            LDAPSearchResults results = ldapConnection.search(
                "dc=example,dc=com",
                LDAPConnection.SCOPE_SUB,
                filter,
                null,
                false
            );
            
            // Process results...
            ldapConnection.disconnect();
        } catch (LDAPException e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_10(@RequestHeader("X-User-Id") String userId, LdapTemplate ldapTemplate) {
        try {
            // ruleid: java-ldap-injection
            String filter = "(|(uid=" + userId + ")(mail=" + userId + "))";
            List<String> result = ldapTemplate.search(
                "dc=example,dc=com",
                filter,
                (AttributesMapper<String>) attrs -> (String) attrs.get("cn").get()
            );
            // Process results...
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_11(HttpServletRequest request) {
        String firstName = request.getParameter("firstName");
        String lastName = request.getParameter("lastName");
        
        try {
            Hashtable<String, Object> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            
            DirContext ctx = new InitialDirContext(env);
            
            // ruleid: java-ldap-injection
            String searchFilter = "(&(givenName=" + firstName + ")(sn=" + lastName + "))";
            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", searchFilter, constraints);
            
            // Process results...
            ctx.close();
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_12(Request request, Response response) {
        String title = request.queryParams("title");
        
        try {
            LDAPConnection connection = new LDAPConnection("localhost", 389);
            connection.bind("cn=admin,dc=example,dc=com", "password");
            
            // ruleid: java-ldap-injection
            String filterString = "(title=" + title + ")";
            com.unboundid.ldap.sdk.Filter filter = com.unboundid.ldap.sdk.Filter.create(filterString);
            
            SearchResult searchResult = connection.search("dc=example,dc=com", 
                                                        com.unboundid.ldap.sdk.SearchScope.SUB, 
                                                        filter);
            
            // Process results...
            connection.close();
        } catch (LDAPException e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_13(io.vertx.ext.web.RoutingContext context) {
        String phoneNumber = context.request().getParam("phone");
        
        try {
            Hashtable<String, Object> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            
            DirContext ctx = new InitialDirContext(env);
            
            // ruleid: java-ldap-injection
            String searchFilter = "(telephoneNumber=" + phoneNumber + ")";
            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", searchFilter, constraints);
            
            // Process results...
            ctx.close();
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_14(HttpServletRequest request) {
        String employeeId = request.getParameter("employeeId");
        
        try {
            org.ldaptive.ConnectionFactory connectionFactory = 
                new org.ldaptive.DefaultConnectionFactory("ldap://localhost:389");
            Connection connection = connectionFactory.getConnection();
            connection.open();
            
            // ruleid: java-ldap-injection
            org.ldaptive.SearchFilter filter = new org.ldaptive.SearchFilter("(employeeNumber=" + employeeId + ")");
            org.ldaptive.SearchOperation search = new org.ldaptive.SearchOperation(connection);
            org.ldaptive.SearchRequest searchRequest = new org.ldaptive.SearchRequest("dc=example,dc=com", filter);
            
            org.ldaptive.SearchResult result = search.execute(searchRequest).getResult();
            
            // Process results...
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_15(HttpServletRequest request) {
        String manager = request.getHeader("X-Manager");
        
        try {
            LdapConnection connection = new LdapNetworkConnection("localhost", 389);
            connection.bind("cn=admin,dc=example,dc=com", "password");
            
            // ruleid: java-ldap-injection
            String filter = "(manager=" + manager + ")";
            org.apache.directory.api.ldap.model.message.SearchRequest searchRequest = 
                new org.apache.directory.api.ldap.model.message.SearchRequestImpl();
            searchRequest.setBase(new org.apache.directory.api.ldap.model.name.Dn("dc=example,dc=com"));
            searchRequest.setFilter(filter);
            searchRequest.setScope(SearchScope.SUBTREE);
            
            org.apache.directory.api.ldap.model.message.SearchCursor cursor = 
                connection.search(searchRequest);
            
            // Process results...
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Safe/Secure Code)
    public static void good_case_1(HttpServletRequest request, HttpServletResponse response) {
        try {
            String username = request.getParameter("username");
            
            // Sanitize input by escaping special characters
            username = StringEscapeUtils.escapeJava(username);
            
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            
            DirContext ctx = new InitialDirContext(env);
            
            // ok: java-ldap-injection
            String searchFilter = "(uid=" + username + ")";
            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", searchFilter, constraints);
            
            // Process results...
            ctx.close();
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_2(@RequestParam String user, LdapTemplate ldapTemplate) {
        try {
            // Using LdapQueryBuilder to safely construct the query
            // ok: java-ldap-injection
            List<String> result = ldapTemplate.search(
                LdapQueryBuilder.query()
                    .base("dc=example,dc=com")
                    .where("objectClass").is("person")
                    .and("uid").is(user),
                (AttributesMapper<String>) attrs -> (String) attrs.get("cn").get()
            );
            // Process results...
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_3(spark.Request req, spark.Response res) {
        String userId = req.queryParams("userId");
        
        try {
            LdapConnection connection = new LdapNetworkConnection("localhost", 389);
            connection.bind("cn=admin,dc=example,dc=com", "password");
            
            // Using proper filter encoding
            // ok: java-ldap-injection
            String filter = "(uid=" + org.apache.directory.api.ldap.model.filter.FilterEncoder.encodeFilterValue(userId) + ")";
            org.apache.directory.api.ldap.model.message.SearchRequest searchRequest = 
                new org.apache.directory.api.ldap.model.message.SearchRequestImpl();
            searchRequest.setBase(new org.apache.directory.api.ldap.model.name.Dn("dc=example,dc=com"));
            searchRequest.setFilter(filter);
            searchRequest.setScope(SearchScope.SUBTREE);
            
            org.apache.directory.api.ldap.model.message.SearchCursor cursor = 
                connection.search(searchRequest);
            
            // Process results...
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_4(io.javalin.http.Context ctx) {
        String email = ctx.queryParam("email");
        
        try {
            LDAPConnection connection = new LDAPConnection("localhost", 389, 
                                                         "cn=admin,dc=example,dc=com", "password");
            
            // Using Filter.createEqualityFilter for safe filter creation
            // ok: java-ldap-injection
            com.unboundid.ldap.sdk.Filter filter = Filter.createEqualityFilter("mail", email);
            
            com.unboundid.ldap.sdk.SearchRequest searchRequest = 
                new com.unboundid.ldap.sdk.SearchRequest("dc=example,dc=com", 
                                                       com.unboundid.ldap.sdk.SearchScope.SUB, 
                                                       filter);
            
            SearchResult result = connection.search(searchRequest);
            
            // Process results...
            connection.close();
        } catch (LDAPException e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_5(HttpExchange exchange) {
        try {
            String query = exchange.getRequestURI().getQuery();
            String[] params = query.split("&");
            String cn = "";
            
            for (String param : params) {
                if (param.startsWith("cn=")) {
                    cn = param.substring(3);
                    break;
                }
            }
            
            // Sanitize the input
            cn = Encode.forLdap(cn);
            
            Hashtable<String, Object> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, "cn=admin,dc=example,dc=com");
            env.put(Context.SECURITY_CREDENTIALS, "password");
            
            DirContext ctx = new InitialDirContext(env);
            
            // ok: java-ldap-injection
            String searchFilter = "(cn=" + cn + ")";
            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", searchFilter, constraints);
            
            // Process results...
            ctx.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_6(RoutingContext routingContext) {
        String group = routingContext.request().getParam("group");
        
        try {
            // Validate input against a whitelist pattern
            Pattern pattern = Pattern.compile("^[a-zA-Z0-9_-]+$");
            if (!pattern.matcher(group).matches()) {
                throw new IllegalArgumentException("Invalid group name");
            }
            
            Hashtable<String, Object> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            
            DirContext ctx = new InitialDirContext(env);
            
            // ok: java-ldap-injection
            String searchFilter = "(&(objectClass=groupOfNames)(cn=" + group + "))";
            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", searchFilter, constraints);
            
            // Process results...
            ctx.close();
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_7(@RequestBody UserRequest userRequest, LdapTemplate ldapTemplate) {
        String username = userRequest.getUsername();
        
        try {
            // Using EqualsFilter for safe filter creation
            // ok: java-ldap-injection
            EqualsFilter filter = new EqualsFilter("sAMAccountName", username);
            List<String> result = ldapTemplate.search(
                "dc=example,dc=com",
                filter.encode(),
                (AttributesMapper<String>) attrs -> (String) attrs.get("displayName").get()
            );
            // Process results...
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_8(ratpack.handling.Context ctx) {
        String department = ctx.getRequest().getQueryParams().get("department");
        
        try {
            org.ldaptive.ConnectionFactory connectionFactory = 
                new org.ldaptive.DefaultConnectionFactory("ldap://localhost:389");
            Connection connection = connectionFactory.getConnection();
            connection.open();
            
            // Using parameterized search filter
            // ok: java-ldap-injection
            org.ldaptive.SearchFilter filter = new org.ldaptive.SearchFilter("(department={0})");
            filter.setParameter(0, department);
            
            org.ldaptive.SearchOperation search = new org.ldaptive.SearchOperation(connection);
            org.ldaptive.SearchRequest request = new org.ldaptive.SearchRequest("dc=example,dc=com", filter);
            
            org.ldaptive.SearchResult result = search.execute(request).getResult();
            
            // Process results...
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_9(HttpServletRequest request) {
        String role = request.getParameter("role");
        
        try {
            // Sanitize input
            role = role.replaceAll("[*()\\\\&|=><~!{}\\[\\]^\"';,]", "");
            
            LDAPConnection ldapConnection = new LDAPConnection();
            ldapConnection.connect("localhost", 389);
            ldapConnection.bind(3, "cn=admin,dc=example,dc=com", "password".getBytes());
            
            // ok: java-ldap-injection
            String filter = "(role=" + role + ")";
            LDAPSearchResults results = ldapConnection.search(
                "dc=example,dc=com",
                LDAPConnection.SCOPE_SUB,
                filter,
                null,
                false
            );
            
            // Process results...
            ldapConnection.disconnect();
        } catch (LDAPException e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_10(@RequestHeader("X-User-Id") String userId, LdapTemplate ldapTemplate) {
        try {
            // Using AndFilter and EqualsFilter for safe filter creation
            // ok: java-ldap-injection
            AndFilter filter = new AndFilter();
            filter.or(new EqualsFilter("uid", userId));
            filter.or(new EqualsFilter("mail", userId));
            
            List<String> result = ldapTemplate.search(
                "dc=example,dc=com",
                filter.encode(),
                (AttributesMapper<String>) attrs -> (String) attrs.get("cn").get()
            );
            // Process results...
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_11(HttpServletRequest request) {
        String firstName = request.getParameter("firstName");
        String lastName = request.getParameter("lastName");
        
        try {
            // Sanitize inputs
            firstName = StringEscapeUtils.escapeJava(firstName);
            lastName = StringEscapeUtils.escapeJava(lastName);
            
            Hashtable<String, Object> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            
            DirContext ctx = new InitialDirContext(env);
            
            // ok: java-ldap-injection
            String searchFilter = "(&(givenName=" + firstName + ")(sn=" + lastName + "))";
            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", searchFilter, constraints);
            
            // Process results...
            ctx.close();
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_12(Request request, Response response) {
        String title = request.queryParams("title");
        
        try {
            LDAPConnection connection = new LDAPConnection("localhost", 389);
            connection.bind("cn=admin,dc=example,dc=com", "password");
            
            // Using proper filter creation method
            // ok: java-ldap-injection
            com.unboundid.ldap.sdk.Filter filter = com.unboundid.ldap.sdk.Filter.createEqualityFilter("title", title);
            
            SearchResult searchResult = connection.search("dc=example,dc=com", 
                                                        com.unboundid.ldap.sdk.SearchScope.SUB, 
                                                        filter);
            
            // Process results...
            connection.close();
        } catch (LDAPException e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_13(io.vertx.ext.web.RoutingContext context) {
        String phoneNumber = context.request().getParam("phone");
        
        try {
            // Validate phone number format
            if (!phoneNumber.matches("^[0-9+\\-\\s()]+$")) {
                throw new IllegalArgumentException("Invalid phone number format");
            }
            
            Hashtable<String, Object> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            
            DirContext ctx = new InitialDirContext(env);
            
            // ok: java-ldap-injection
            String searchFilter = "(telephoneNumber=" + phoneNumber + ")";
            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", searchFilter, constraints);
            
            // Process results...
            ctx.close();
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_14(HttpServletRequest request) {
        String employeeId = request.getParameter("employeeId");
        
        try {
            org.ldaptive.ConnectionFactory connectionFactory = 
                new org.ldaptive.DefaultConnectionFactory("ldap://localhost:389");
            Connection connection = connectionFactory.getConnection();
            connection.open();
            
            // Using parameterized search filter
            // ok: java-ldap-injection
            org.ldaptive.SearchFilter filter = new org.ldaptive.SearchFilter("(employeeNumber={0})");
            filter.setParameter(0, employeeId);
            
            org.ldaptive.SearchOperation search = new org.ldaptive.SearchOperation(connection);
            org.ldaptive.SearchRequest searchRequest = new org.ldaptive.SearchRequest("dc=example,dc=com", filter);
            
            org.ldaptive.SearchResult result = search.execute(searchRequest).getResult();
            
            // Process results...
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_15(HttpServletRequest request) {
        String manager = request.getHeader("X-Manager");
        
        try {
            // Sanitize the input using OWASP Encoder
            manager = Encode.forLdap(manager);
            
            LdapConnection connection = new LdapNetworkConnection("localhost", 389);
            connection.bind("cn=admin,dc=example,dc=com", "password");
            
            // ok: java-ldap-injection
            String filter = "(manager=" + manager + ")";
            org.apache.directory.api.ldap.model.message.SearchRequest searchRequest = 
                new org.apache.directory.api.ldap.model.message.SearchRequestImpl();
            searchRequest.setBase(new org.apache.directory.api.ldap.model.name.Dn("dc=example,dc=com"));
            searchRequest.setFilter(filter);
            searchRequest.setScope(SearchScope.SUBTREE);
            
            org.apache.directory.api.ldap.model.message.SearchCursor cursor = 
                connection.search(searchRequest);
            
            // Process results...
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Helper class for examples
    private static class UserRequest {
        private String username;
        
        public String getUsername() {
            return username;
        }
        
        public void setUsername(String username) {
            this.username = username;
        }
    }
}
// {/fact}