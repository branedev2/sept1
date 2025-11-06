import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;
import org.apache.directory.ldap.client.api.*;
import org.springframework.ldap.core.*;
import org.springframework.ldap.query.*;
import com.unboundid.ldap.sdk.*;
import org.apache.commons.lang3.StringEscapeUtils;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import java.util.regex.Pattern;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.InitialLdapContext;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.template.LdapConnectionTemplate;
import org.apache.directory.ldap.client.template.EntryMapper;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpHeaders;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

// Security Issue: LDAP Injection Vulnerabilities in Java Applications

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    try {
        String username = request.getParameter("username");
        
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");
        
        DirContext ctx = new InitialDirContext(env);
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        
        // ruleid: java-ldap-injection-exp
        NamingEnumeration<SearchResult> results = ctx.search("ou=users,dc=example,dc=com", 
                "(uid=" + username + ")", sc);
        
        while (results.hasMore()) {
            SearchResult result = results.next();
            System.out.println(result.getName());
        }
        ctx.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_2(HttpServletRequest request) {
    try {
        String userInput = request.getParameter("searchTerm");
        
        LdapConnection connection = new LdapNetworkConnection("localhost", 389);
        connection.bind("cn=admin,dc=example,dc=com", "password");
        
        SearchRequest searchRequest = new SearchRequest();
        searchRequest.setScope(SearchScope.SUBTREE);
        searchRequest.setBase(new Dn("ou=users,dc=example,dc=com"));
        
        // ruleid: java-ldap-injection-exp
        searchRequest.setFilter("(cn=" + userInput + ")");
        
        SearchCursor cursor = connection.search(searchRequest);
        while (cursor.next()) {
            Entry entry = cursor.getEntry();
            System.out.println(entry.getDn());
        }
        connection.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@RestController
public void bad_case_3(@RequestParam String query, HttpServletRequest request) {
    try {
        String filter = request.getParameter("filter");
        
        LdapTemplate ldapTemplate = new LdapTemplate();
        ldapTemplate.setContextSource(getContextSource());
        
        // ruleid: java-ldap-injection-exp
        List<String> result = ldapTemplate.search(
            "ou=people", 
            "(&(objectClass=person)(cn=" + filter + "))", 
            (AttributesMapper<String>) attrs -> (String) attrs.get("cn").get());
        
        for (String name : result) {
            System.out.println(name);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_4(HttpServletRequest request) {
    try {
        String userId = request.getParameter("id");
        
        LDAPConnection connection = new LDAPConnection("localhost", 389, 
                                    "cn=admin,dc=example,dc=com", "password");
        
        // ruleid: java-ldap-injection-exp
        SearchResult searchResult = connection.search("dc=example,dc=com", 
                                   SearchScope.SUB, "(uid=" + userId + ")");
        
        for (SearchResultEntry entry : searchResult.getSearchEntries()) {
            System.out.println(entry.getDN());
        }
        connection.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5(HttpServletRequest request) {
    try {
        String userName = request.getParameter("username");
        
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, "cn=admin,dc=example,dc=com");
        env.put(Context.SECURITY_CREDENTIALS, "password");
        
        LdapContext ctx = new InitialLdapContext(env, null);
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        
        // ruleid: java-ldap-injection-exp
        NamingEnumeration<SearchResult> results = ctx.search(
            "dc=example,dc=com", 
            "(&(objectClass=person)(sAMAccountName=" + userName + "))", 
            searchControls);
        
        while (results.hasMoreElements()) {
            SearchResult result = results.nextElement();
            System.out.println(result.getNameInNamespace());
        }
        ctx.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@GetMapping("/ldap-search")
public void bad_case_6(HttpServletRequest request) {
    try {
        String department = request.getParameter("dept");
        
        LdapConnectionTemplate template = new LdapConnectionTemplate();
        template.setConnectionFactory(getConnectionFactory());
        
        // ruleid: java-ldap-injection-exp
        List<String> users = template.search(
            "ou=people,dc=example,dc=com",
            "(department=" + department + ")",
            new EntryMapper<String>() {
                @Override
                public String map(Entry entry) throws LdapException {
                    return entry.get("cn").getString();
                }
            });
        
        for (String user : users) {
            System.out.println(user);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7(HttpServletRequest request) {
    try {
        String email = request.getParameter("email");
        
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");
        
        DirContext ctx = new InitialDirContext(env);
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        
        // ruleid: java-ldap-injection-exp
        String filter = "(mail=" + email + ")";
        NamingEnumeration<SearchResult> results = ctx.search("ou=users,dc=example,dc=com", filter, sc);
        
        while (results.hasMore()) {
            SearchResult result = results.next();
            System.out.println(result.getName());
        }
        ctx.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@RestController
@RequestMapping("/api/users")
public void bad_case_8(@RequestHeader("X-User-Filter") String userFilter) {
    try {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer token123");
        
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(
            "https://api.example.com/users?filter=" + userFilter, 
            HttpMethod.GET, entity, String.class);
        
        String filter = response.getBody();
        
        LdapTemplate ldapTemplate = new LdapTemplate();
        ldapTemplate.setContextSource(getContextSource());
        
        // ruleid: java-ldap-injection-exp
        List<String> result = ldapTemplate.search(
            "ou=people", 
            "(uid=" + filter + ")", 
            (AttributesMapper<String>) attrs -> (String) attrs.get("uid").get());
        
        for (String uid : result) {
            System.out.println(uid);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9(HttpServletRequest request) {
    try {
        String group = request.getParameter("group");
        
        LDAPConnection connection = new LDAPConnection("ldap.example.com", 389);
        connection.bind("cn=admin,dc=example,dc=com", "password");
        
        // ruleid: java-ldap-injection-exp
        Filter filter = Filter.create("(&(objectClass=groupOfNames)(cn=" + group + "))");
        SearchRequest searchRequest = new SearchRequest("dc=example,dc=com", 
                                     SearchScope.SUB, filter);
        
        SearchResult result = connection.search(searchRequest);
        for (SearchResultEntry entry : result.getSearchEntries()) {
            System.out.println(entry.getDN());
        }
        connection.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10(HttpServletRequest request) {
    try {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet("https://api.example.com/users");
        org.apache.http.HttpResponse response = httpClient.execute(httpGet);
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(
                response.getEntity().getContent()));
        String userInput = reader.readLine();
        httpClient.close();
        
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");
        
        DirContext ctx = new InitialDirContext(env);
        
        // ruleid: java-ldap-injection-exp
        String searchFilter = "(|(uid=" + userInput + ")(cn=" + userInput + "))";
        NamingEnumeration<SearchResult> results = ctx.search(
            "ou=users,dc=example,dc=com", searchFilter, new SearchControls());
        
        while (results.hasMore()) {
            System.out.println(results.next().getName());
        }
        ctx.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11(HttpServletRequest request) {
    try {
        OkHttpClient client = new OkHttpClient();
        Request httpRequest = new Request.Builder()
            .url("https://api.example.com/search?q=" + request.getParameter("q"))
            .build();
        
        Response response = client.newCall(httpRequest).execute();
        String searchTerm = response.body().string();
        
        LdapTemplate ldapTemplate = new LdapTemplate();
        ldapTemplate.setContextSource(getContextSource());
        
        // ruleid: java-ldap-injection-exp
        List<String> users = ldapTemplate.search(
            LdapQueryBuilder.query().base("dc=example,dc=com")
                .where("objectclass").is("person")
                .and("cn").like(searchTerm + "*"),
            (AttributesMapper<String>) attrs -> (String) attrs.get("cn").get());
        
        for (String user : users) {
            System.out.println(user);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12(HttpServletRequest request) {
    try {
        String role = request.getParameter("role");
        
        URL url = new URL("https://localhost:8080/api/ldap");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        
        LDAPConnection connection = new LDAPConnection("ldap.example.com", 389,
                                   "cn=admin,dc=example,dc=com", "password");
        
        // ruleid: java-ldap-injection-exp
        SearchResultEntry entry = connection.searchForEntry(
            "dc=example,dc=com",
            SearchScope.SUB,
            "(employeeType=" + role + ")");
        
        if (entry != null) {
            System.out.println("Found: " + entry.getDN());
        }
        connection.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13(HttpServletRequest request) {
    try {
        String title = request.getParameter("title");
        
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");
        
        DirContext ctx = new InitialDirContext(env);
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        
        // ruleid: java-ldap-injection-exp
        StringBuilder filterBuilder = new StringBuilder();
        filterBuilder.append("(&(objectClass=person)(title=");
        filterBuilder.append(title);
        filterBuilder.append("))");
        
        NamingEnumeration<SearchResult> results = ctx.search(
            "ou=employees,dc=example,dc=com", 
            filterBuilder.toString(), 
            sc);
        
        while (results.hasMore()) {
            SearchResult result = results.next();
            System.out.println(result.getName());
        }
        ctx.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14(HttpServletRequest request) {
    try {
        HttpServletRequest currentRequest = ((ServletRequestAttributes) RequestContextHolder
            .currentRequestAttributes()).getRequest();
        String location = currentRequest.getParameter("location");
        
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl("ldap://localhost:389");
        contextSource.setBase("dc=example,dc=com");
        contextSource.afterPropertiesSet();
        
        LdapTemplate ldapTemplate = new LdapTemplate(contextSource);
        
        // ruleid: java-ldap-injection-exp
        String filter = "(&(objectClass=organizationalUnit)(l=" + location + "))";
        List<String> units = ldapTemplate.search(
            "", 
            filter,
            (AttributesMapper<String>) attrs -> (String) attrs.get("ou").get());
        
        for (String unit : units) {
            System.out.println(unit);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15(HttpServletRequest request) {
    try {
        String phoneNumber = request.getParameter("phone");
        
        LdapConnection connection = new LdapNetworkConnection("localhost", 389);
        connection.bind("cn=admin,dc=example,dc=com", "password");
        
        EntryCursor cursor;
        
        // ruleid: java-ldap-injection-exp
        cursor = connection.search("ou=people,dc=example,dc=com", 
                 "(telephoneNumber=" + phoneNumber + ")", 
                 SearchScope.ONELEVEL);
        
        for (Entry entry : cursor) {
            System.out.println(entry.getDn());
        }
        connection.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    try {
        String username = request.getParameter("username");
        
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");
        
        DirContext ctx = new InitialDirContext(env);
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        
        // Escape the input to prevent LDAP injection
        // ok: java-ldap-injection-exp
        NamingEnumeration<SearchResult> results = ctx.search("ou=users,dc=example,dc=com", 
                "(uid={0})", new Object[]{username}, sc);
        
        while (results.hasMore()) {
            SearchResult result = results.next();
            System.out.println(result.getName());
        }
        ctx.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_2(HttpServletRequest request) {
    try {
        String userInput = request.getParameter("searchTerm");
        
        LdapConnection connection = new LdapNetworkConnection("localhost", 389);
        connection.bind("cn=admin,dc=example,dc=com", "password");
        
        SearchRequest searchRequest = new SearchRequest();
        searchRequest.setScope(SearchScope.SUBTREE);
        searchRequest.setBase(new Dn("ou=users,dc=example,dc=com"));
        
        // Use proper escaping for LDAP filter
        // ok: java-ldap-injection-exp
        searchRequest.setFilter("(cn=" + LdapUtils.escapeForFilter(userInput) + ")");
        
        SearchCursor cursor = connection.search(searchRequest);
        while (cursor.next()) {
            Entry entry = cursor.getEntry();
            System.out.println(entry.getDn());
        }
        connection.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@RestController
public void good_case_3(@RequestParam String query, HttpServletRequest request) {
    try {
        String filter = request.getParameter("filter");
        
        LdapTemplate ldapTemplate = new LdapTemplate();
        ldapTemplate.setContextSource(getContextSource());
        
        // Use query builder with proper parameter binding
        // ok: java-ldap-injection-exp
        List<String> result = ldapTemplate.search(
            Query.query().where("objectClass").is("person").and("cn").is(filter),
            (AttributesMapper<String>) attrs -> (String) attrs.get("cn").get());
        
        for (String name : result) {
            System.out.println(name);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_4(HttpServletRequest request) {
    try {
        String userId = request.getParameter("id");
        
        LDAPConnection connection = new LDAPConnection("localhost", 389, 
                                    "cn=admin,dc=example,dc=com", "password");
        
        // Use Filter.createEqualityFilter for safe parameter handling
        // ok: java-ldap-injection-exp
        Filter filter = Filter.createEqualityFilter("uid", userId);
        SearchRequest searchRequest = new SearchRequest("dc=example,dc=com", 
                                     SearchScope.SUB, filter);
        
        SearchResult searchResult = connection.search(searchRequest);
        for (SearchResultEntry entry : searchResult.getSearchEntries()) {
            System.out.println(entry.getDN());
        }
        connection.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5(HttpServletRequest request) {
    try {
        String userName = request.getParameter("username");
        
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, "cn=admin,dc=example,dc=com");
        env.put(Context.SECURITY_CREDENTIALS, "password");
        
        LdapContext ctx = new InitialLdapContext(env, null);
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        
        // Use parameterized search with replacement
        // ok: java-ldap-injection-exp
        NamingEnumeration<SearchResult> results = ctx.search(
            "dc=example,dc=com", 
            "(&(objectClass=person)(sAMAccountName={0}))", 
            new Object[]{userName}, 
            searchControls);
        
        while (results.hasMoreElements()) {
            SearchResult result = results.nextElement();
            System.out.println(result.getNameInNamespace());
        }
        ctx.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@GetMapping("/ldap-search")
public void good_case_6(HttpServletRequest request) {
    try {
        String department = request.getParameter("dept");
        
        LdapConnectionTemplate template = new LdapConnectionTemplate();
        template.setConnectionFactory(getConnectionFactory());
        
        // Use proper escaping for LDAP search
        // ok: java-ldap-injection-exp
        String escapedDepartment = org.apache.directory.api.ldap.model.filter.FilterEncoder.encodeFilterValue(department);
        List<String> users = template.search(
            "ou=people,dc=example,dc=com",
            "(department=" + escapedDepartment + ")",
            new EntryMapper<String>() {
                @Override
                public String map(Entry entry) throws LdapException {
                    return entry.get("cn").getString();
                }
            });
        
        for (String user : users) {
            System.out.println(user);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7(HttpServletRequest request) {
    try {
        String email = request.getParameter("email");
        
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");
        
        DirContext ctx = new InitialDirContext(env);
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        
        // Use a regex pattern to validate email format before using in LDAP query
        Pattern emailPattern = Pattern.compile("^[A-Za-z0-9+_.-]+@(.+)$");
        if (!emailPattern.matcher(email).matches()) {
            throw new IllegalArgumentException("Invalid email format");
        }
        
        // ok: java-ldap-injection-exp
        String escapedEmail = StringEscapeUtils.escapeJava(email);
        String filter = "(mail=" + escapedEmail + ")";
        NamingEnumeration<SearchResult> results = ctx.search("ou=users,dc=example,dc=com", filter, sc);
        
        while (results.hasMore()) {
            SearchResult result = results.next();
            System.out.println(result.getName());
        }
        ctx.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@RestController
@RequestMapping("/api/users")
public void good_case_8(@RequestHeader("X-User-Filter") String userFilter) {
    try {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer token123");
        
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(
            "https://api.example.com/users?filter=" + userFilter, 
            HttpMethod.GET, entity, String.class);
        
        String filter = response.getBody();
        
        LdapTemplate ldapTemplate = new LdapTemplate();
        ldapTemplate.setContextSource(getContextSource());
        
        // Use LdapQueryBuilder for safe parameter binding
        // ok: java-ldap-injection-exp
        List<String> result = ldapTemplate.search(
            LdapQueryBuilder.query().base("ou=people").where("uid").is(filter),
            (AttributesMapper<String>) attrs -> (String) attrs.get("uid").get());
        
        for (String uid : result) {
            System.out.println(uid);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9(HttpServletRequest request) {
    try {
        String group = request.getParameter("group");
        
        LDAPConnection connection = new LDAPConnection("ldap.example.com", 389);
        connection.bind("cn=admin,dc=example,dc=com", "password");
        
        // Use Filter.createANDFilter and Filter.createEqualityFilter for safe filtering
        // ok: java-ldap-injection-exp
        Filter objectClassFilter = Filter.createEqualityFilter("objectClass", "groupOfNames");
        Filter groupFilter = Filter.createEqualityFilter("cn", group);
        Filter filter = Filter.createANDFilter(objectClassFilter, groupFilter);
        
        SearchRequest searchRequest = new SearchRequest("dc=example,dc=com", 
                                     SearchScope.SUB, filter);
        
        SearchResult result = connection.search(searchRequest);
        for (SearchResultEntry entry : result.getSearchEntries()) {
            System.out.println(entry.getDN());
        }
        connection.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10(HttpServletRequest request) {
    try {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet("https://api.example.com/users");
        org.apache.http.HttpResponse response = httpClient.execute(httpGet);
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(
                response.getEntity().getContent()));
        String userInput = reader.readLine();
        httpClient.close();
        
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");
        
        DirContext ctx = new InitialDirContext(env);
        
        // Use JNDI parameter substitution
        // ok: java-ldap-injection-exp
        String searchFilter = "(|(uid={0})(cn={0}))";
        NamingEnumeration<SearchResult> results = ctx.search(
            "ou=users,dc=example,dc=com", searchFilter, new Object[]{userInput}, new SearchControls());
        
        while (results.hasMore()) {
            System.out.println(results.next().getName());
        }
        ctx.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11(HttpServletRequest request) {
    try {
        OkHttpClient client = new OkHttpClient();
        Request httpRequest = new Request.Builder()
            .url("https://api.example.com/search?q=" + request.getParameter("q"))
            .build();
        
        Response response = client.newCall(httpRequest).execute();
        String searchTerm = response.body().string();
        
        LdapTemplate ldapTemplate = new LdapTemplate();
        ldapTemplate.setContextSource(getContextSource());
        
        // Use ContainerCriteria for safe parameter binding
        // ok: java-ldap-injection-exp
        ContainerCriteria criteria = LdapQueryBuilder.query()
            .base("dc=example,dc=com")
            .where("objectclass").is("person");
        
        if (searchTerm != null && !searchTerm.isEmpty()) {
            criteria = criteria.and("cn").like(searchTerm + "*");
        }
        
        List<String> users = ldapTemplate.search(criteria,
            (AttributesMapper<String>) attrs -> (String) attrs.get("cn").get());
        
        for (String user : users) {
            System.out.println(user);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12(HttpServletRequest request) {
    try {
        String role = request.getParameter("role");
        
        URL url = new URL("https://localhost:8080/api/ldap");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        
        LDAPConnection connection = new LDAPConnection("ldap.example.com", 389,
                                   "cn=admin,dc=example,dc=com", "password");
        
        // Use OWASP ESAPI for encoding
        Encoder encoder = ESAPI.encoder();
        String encodedRole = encoder.encodeForLDAP(role);
        
        // ok: java-ldap-injection-exp
        SearchResultEntry entry = connection.searchForEntry(
            "dc=example,dc=com",
            SearchScope.SUB,
            "(employeeType=" + encodedRole + ")");
        
        if (entry != null) {
            System.out.println("Found: " + entry.getDN());
        }
        connection.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13(HttpServletRequest request) {
    try {
        String title = request.getParameter("title");
        
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");
        
        DirContext ctx = new InitialDirContext(env);
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        
        // Validate input against a whitelist
        if (!isValidTitle(title)) {
            throw new IllegalArgumentException("Invalid title");
        }
        
        // ok: java-ldap-injection-exp
        NamingEnumeration<SearchResult> results = ctx.search(
            "ou=employees,dc=example,dc=com", 
            "(&(objectClass=person)(title={0}))", 
            new Object[]{title},
            sc);
        
        while (results.hasMore()) {
            SearchResult result = results.next();
            System.out.println(result.getName());
        }
        ctx.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14(HttpServletRequest request) {
    try {
        HttpServletRequest currentRequest = ((ServletRequestAttributes) RequestContextHolder
            .currentRequestAttributes()).getRequest();
        String location = currentRequest.getParameter("location");
        
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl("ldap://localhost:389");
        contextSource.setBase("dc=example,dc=com");
        contextSource.afterPropertiesSet();
        
        LdapTemplate ldapTemplate = new LdapTemplate(contextSource);
        
        // Use Spring LDAP's query builder
        // ok: java-ldap-injection-exp
        List<String> units = ldapTemplate.search(
            Query.query().where("objectClass").is("organizationalUnit").and("l").is(location),
            (AttributesMapper<String>) attrs -> (String) attrs.get("ou").get());
        
        for (String unit : units) {
            System.out.println(unit);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15(HttpServletRequest request) {
    try {
        String phoneNumber = request.getParameter("phone");
        
        // Validate phone number format
        if (!phoneNumber.matches("^\\+?[0-9\\s-]+$")) {
            throw new IllegalArgumentException("Invalid phone number format");
        }
        
        LdapConnection connection = new LdapNetworkConnection("localhost", 389);
        connection.bind("cn=admin,dc=example,dc=com", "password");
        
        // Use proper escaping for LDAP search
        // ok: java-ldap-injection-exp
        String escapedPhoneNumber = org.apache.directory.api.ldap.model.filter.FilterEncoder.encodeFilterValue(phoneNumber);
        EntryCursor cursor = connection.search("ou=people,dc=example,dc=com", 
                           "(telephoneNumber=" + escapedPhoneNumber + ")", 
                           SearchScope.ONELEVEL);
        
        for (Entry entry : cursor) {
            System.out.println(entry.getDn());
        }
        connection.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// Helper method for good_case_13
private boolean isValidTitle(String title) {
    String[] validTitles = {"Manager", "Developer", "Director", "Analyst", "Engineer"};
    for (String validTitle : validTitles) {
        if (validTitle.equals(title)) {
            return true;
        }
    }
    return false;
}

// Helper method for good_case_3 and others
private LdapContextSource getContextSource() {
    LdapContextSource contextSource = new LdapContextSource();
    contextSource.setUrl("ldap://localhost:389");
    contextSource.setUserDn("cn=admin,dc=example,dc=com");
    contextSource.setPassword("password");
    return contextSource;
}

// Helper method for good_case_6
private LdapConnectionFactory getConnectionFactory() {
    DefaultLdapConnectionFactory factory = new DefaultLdapConnectionFactory("localhost", 389);
    factory.setTimeOut(30000);
    return factory;
}