import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Hashtable;
import java.util.regex.Pattern;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.apache.commons.text.StringEscapeUtils;

public class LdapInjectionExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=ldap-injection@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String username = request.getParameter("username");
        
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389/dc=example,dc=com");
        DirContext ctx = new InitialDirContext(env);
        
        SearchControls ctls = new SearchControls();
        ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        
        // ruleid: java-ldap-injection
        NamingEnumeration<SearchResult> results = ctx.search("", "(uid=" + username + ")", ctls);
        
        while (results.hasMore()) {
            SearchResult result = results.next();
            response.getWriter().println(result.getNameInNamespace());
        }
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String email = request.getParameter("email");
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        // ruleid: java-ldap-injection
        NamingEnumeration<SearchResult> results = ctx.search("ou=users,dc=example,dc=com", 
                "(&(objectClass=person)(mail=" + email + "))", ctls);
        
        processResults(results, response);
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String lastName = request.getParameter("lastName");
        String firstName = request.getParameter("firstName");
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        // ruleid: java-ldap-injection
        String filter = "(&(sn=" + lastName + ")(givenName=" + firstName + "))";
        NamingEnumeration<SearchResult> results = ctx.search("ou=people", filter, ctls);
        
        processResults(results, response);
    }

    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String groupName = request.getParameter("group");
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        ctls.setSearchScope(SearchControls.ONELEVEL_SCOPE);
        
        String baseDN = "ou=groups,dc=example,dc=com";
        // ruleid: java-ldap-injection
        String filter = "(cn=" + groupName + ")";
        NamingEnumeration<SearchResult> results = ctx.search(baseDN, filter, ctls);
        
        processResults(results, response);
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String employeeId = request.getParameter("employeeId");
        String department = request.getParameter("department");
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        StringBuilder filterBuilder = new StringBuilder();
        filterBuilder.append("(&(employeeID=").append(employeeId).append(")");
        filterBuilder.append("(department=").append(department).append("))");
        
        // ruleid: java-ldap-injection
        NamingEnumeration<SearchResult> results = ctx.search("ou=employees", 
                filterBuilder.toString(), ctls);
        
        processResults(results, response);
    }

    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws NamingException, IOException {
        String userId = request.getHeader("X-User-ID");
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        // ruleid: java-ldap-injection
        NamingEnumeration<SearchResult> results = ctx.search("ou=users", 
                "(uid=" + userId + ")", ctls);
        
        if (!results.hasMore()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
    }

    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String role = request.getParameter("role");
        String company = request.getParameter("company");
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        // ruleid: java-ldap-injection
        String filter = String.format("(&(role=%s)(company=%s))", role, company);
        NamingEnumeration<SearchResult> results = ctx.search("ou=roles", filter, ctls);
        
        processResults(results, response);
    }

    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String[] usernames = request.getParameterValues("usernames");
        
        if (usernames != null && usernames.length > 0) {
            DirContext ctx = getDirContext();
            SearchControls ctls = new SearchControls();
            
            StringBuilder filter = new StringBuilder("(|");
            for (String username : usernames) {
                filter.append("(uid=").append(username).append(")");
            }
            filter.append(")");
            
            // ruleid: java-ldap-injection
            NamingEnumeration<SearchResult> results = ctx.search("ou=users", filter.toString(), ctls);
            
            processResults(results, response);
        }
    }

    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String searchTerm = request.getParameter("search");
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        // ruleid: java-ldap-injection
        String filter = "(|(cn=*" + searchTerm + "*)(sn=*" + searchTerm + "*)(mail=*" + searchTerm + "*))";
        NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", filter, ctls);
        
        processResults(results, response);
    }

    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String attribute = request.getParameter("attribute");
        String value = request.getParameter("value");
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        // ruleid: java-ldap-injection
        String filter = "(" + attribute + "=" + value + ")";
        NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", filter, ctls);
        
        processResults(results, response);
    }

    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String username = request.getParameter("username");
        
        // Simple attempt to sanitize but still vulnerable
        username = username.replace("*", "");
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        // ruleid: java-ldap-injection
        NamingEnumeration<SearchResult> results = ctx.search("ou=users", 
                "(uid=" + username + ")", ctls);
        
        processResults(results, response);
    }

    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String baseDN = request.getParameter("baseDN");
        String filter = "(objectClass=person)";
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        // ruleid: java-ldap-injection
        NamingEnumeration<SearchResult> results = ctx.search(baseDN, filter, ctls);
        
        processResults(results, response);
    }

    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        // ruleid: java-ldap-injection
        String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";
        NamingEnumeration<SearchResult> results = ctx.search("ou=users", filter, ctls);
        
        if (results.hasMore()) {
            // Authentication successful
        }
    }

    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String phoneNumber = request.getParameter("phone");
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        // ruleid: java-ldap-injection
        NamingEnumeration<SearchResult> results = ctx.search("ou=contacts", 
                "(&(objectClass=person)(telephoneNumber=" + phoneNumber + "))", ctls);
        
        processResults(results, response);
    }

    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String country = request.getParameter("country");
        String state = request.getParameter("state");
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        String filter = "(&(c=" + country + ")";
        if (state != null && !state.isEmpty()) {
            filter += "(st=" + state + ")";
        }
        filter += ")";
        
        // ruleid: java-ldap-injection
        NamingEnumeration<SearchResult> results = ctx.search("ou=locations", filter, ctls);
        
        processResults(results, response);
    }

    // True Negative Examples (Safe Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String username = request.getParameter("username");
        
        // Sanitize input by escaping special characters
        // ok: java-ldap-injection
        username = escapeLDAPSearchFilter(username);
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        NamingEnumeration<SearchResult> results = ctx.search("", "(uid=" + username + ")", ctls);
        
        processResults(results, response);
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String email = request.getParameter("email");
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        // Using JNDI search with separate filter arguments (safe)
        // ok: java-ldap-injection
        Object[] filterArgs = new Object[]{email};
        NamingEnumeration<SearchResult> results = ctx.search("ou=users,dc=example,dc=com", 
                "(&(objectClass=person)(mail={0}))", filterArgs, ctls);
        
        processResults(results, response);
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String lastName = request.getParameter("lastName");
        String firstName = request.getParameter("firstName");
        
        // Sanitize inputs
        // ok: java-ldap-injection
        lastName = escapeLDAPSearchFilter(lastName);
        firstName = escapeLDAPSearchFilter(firstName);
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        String filter = "(&(sn=" + lastName + ")(givenName=" + firstName + "))";
        NamingEnumeration<SearchResult> results = ctx.search("ou=people", filter, ctls);
        
        processResults(results, response);
    }

    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String groupName = request.getParameter("group");
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        ctls.setSearchScope(SearchControls.ONELEVEL_SCOPE);
        
        String baseDN = "ou=groups,dc=example,dc=com";
        
        // Using parameterized search
        // ok: java-ldap-injection
        Object[] filterArgs = new Object[]{groupName};
        NamingEnumeration<SearchResult> results = ctx.search(baseDN, "(cn={0})", filterArgs, ctls);
        
        processResults(results, response);
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String employeeId = request.getParameter("employeeId");
        String department = request.getParameter("department");
        
        // Sanitize inputs
        // ok: java-ldap-injection
        employeeId = escapeLDAPSearchFilter(employeeId);
        department = escapeLDAPSearchFilter(department);
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        StringBuilder filterBuilder = new StringBuilder();
        filterBuilder.append("(&(employeeID=").append(employeeId).append(")");
        filterBuilder.append("(department=").append(department).append("))");
        
        NamingEnumeration<SearchResult> results = ctx.search("ou=employees", 
                filterBuilder.toString(), ctls);
        
        processResults(results, response);
    }

    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws NamingException, IOException {
        String userId = request.getHeader("X-User-ID");
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        // Using parameterized search with header value
        // ok: java-ldap-injection
        Object[] filterArgs = new Object[]{userId};
        NamingEnumeration<SearchResult> results = ctx.search("ou=users", 
                "(uid={0})", filterArgs, ctls);
        
        if (!results.hasMore()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
    }

    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String role = request.getParameter("role");
        String company = request.getParameter("company");
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        // Using parameterized search with multiple arguments
        // ok: java-ldap-injection
        Object[] filterArgs = new Object[]{role, company};
        NamingEnumeration<SearchResult> results = ctx.search("ou=roles", 
                "(&(role={0})(company={1}))", filterArgs, ctls);
        
        processResults(results, response);
    }

    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String[] usernames = request.getParameterValues("usernames");
        
        if (usernames != null && usernames.length > 0) {
            DirContext ctx = getDirContext();
            SearchControls ctls = new SearchControls();
            
            // Sanitize each username
            // ok: java-ldap-injection
            StringBuilder filter = new StringBuilder("(|");
            for (String username : usernames) {
                filter.append("(uid=").append(escapeLDAPSearchFilter(username)).append(")");
            }
            filter.append(")");
            
            NamingEnumeration<SearchResult> results = ctx.search("ou=users", filter.toString(), ctls);
            
            processResults(results, response);
        }
    }

    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String searchTerm = request.getParameter("search");
        
        // Using OWASP ESAPI for encoding
        Encoder encoder = ESAPI.encoder();
        // ok: java-ldap-injection
        String encodedSearchTerm = encoder.encodeForLDAP(searchTerm);
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        String filter = "(|(cn=*" + encodedSearchTerm + "*)(sn=*" + encodedSearchTerm + "*)(mail=*" + encodedSearchTerm + "*))";
        NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", filter, ctls);
        
        processResults(results, response);
    }

    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String value = request.getParameter("value");
        
        // Validate attribute name against a whitelist
        String attribute = request.getParameter("attribute");
        // ok: java-ldap-injection
        if (!isValidAttributeName(attribute)) {
            attribute = "cn"; // Default to a safe attribute
        }
        
        value = escapeLDAPSearchFilter(value);
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        String filter = "(" + attribute + "=" + value + ")";
        NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", filter, ctls);
        
        processResults(results, response);
    }

    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String username = request.getParameter("username");
        
        // Input validation using regex pattern
        // ok: java-ldap-injection
        if (!Pattern.matches("[a-zA-Z0-9_-]{3,20}", username)) {
            throw new IllegalArgumentException("Invalid username format");
        }
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        NamingEnumeration<SearchResult> results = ctx.search("ou=users", 
                "(uid=" + username + ")", ctls);
        
        processResults(results, response);
    }

    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        // Whitelist approach for baseDN
        String requestedBase = request.getParameter("baseDN");
        
        // ok: java-ldap-injection
        String baseDN;
        switch (requestedBase) {
            case "users":
                baseDN = "ou=users,dc=example,dc=com";
                break;
            case "groups":
                baseDN = "ou=groups,dc=example,dc=com";
                break;
            default:
                baseDN = "dc=example,dc=com";
        }
        
        String filter = "(objectClass=person)";
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        NamingEnumeration<SearchResult> results = ctx.search(baseDN, filter, ctls);
        
        processResults(results, response);
    }

    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        // Using parameterized search for authentication
        // ok: java-ldap-injection
        Object[] filterArgs = new Object[]{username, password};
        NamingEnumeration<SearchResult> results = ctx.search("ou=users", 
                "(&(uid={0})(userPassword={1}))", filterArgs, ctls);
        
        if (results.hasMore()) {
            // Authentication successful
        }
    }

    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String phoneNumber = request.getParameter("phone");
        
        // Using StringEscapeUtils from Apache Commons Text
        // ok: java-ldap-injection
        String escapedPhone = StringEscapeUtils.escapeJava(phoneNumber);
        escapedPhone = escapeLDAPSearchFilter(escapedPhone);
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        NamingEnumeration<SearchResult> results = ctx.search("ou=contacts", 
                "(&(objectClass=person)(telephoneNumber=" + escapedPhone + "))", ctls);
        
        processResults(results, response);
    }

    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws NamingException {
        String country = request.getParameter("country");
        String state = request.getParameter("state");
        
        DirContext ctx = getDirContext();
        SearchControls ctls = new SearchControls();
        
        // Using prepared filter with array of arguments
        // ok: java-ldap-injection
        if (state != null && !state.isEmpty()) {
            Object[] filterArgs = new Object[]{country, state};
            NamingEnumeration<SearchResult> results = ctx.search("ou=locations", 
                    "(&(c={0})(st={1}))", filterArgs, ctls);
            processResults(results, response);
        } else {
            Object[] filterArgs = new Object[]{country};
            NamingEnumeration<SearchResult> results = ctx.search("ou=locations", 
                    "(c={0})", filterArgs, ctls);
            processResults(results, response);
        }
    }

    // Helper methods
    private DirContext getDirContext() throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389/dc=example,dc=com");
        return new InitialDirContext(env);
    }

    private void processResults(NamingEnumeration<SearchResult> results, HttpServletResponse response) throws NamingException {
        try {
            while (results.hasMore()) {
                SearchResult result = results.next();
                response.getWriter().println(result.getNameInNamespace());
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String escapeLDAPSearchFilter(String filter) {
        if (filter == null) {
            return null;
        }
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < filter.length(); i++) {
            char c = filter.charAt(i);
            switch (c) {
                case '\\':
                    sb.append("\\5c");
                    break;
                case '*':
                    sb.append("\\2a");
                    break;
                case '(':
                    sb.append("\\28");
                    break;
                case ')':
                    sb.append("\\29");
                    break;
                case '\u0000':
                    sb.append("\\00");
                    break;
                default:
                    sb.append(c);
            }
        }
        return sb.toString();
    }

    private boolean isValidAttributeName(String attribute) {
        String[] validAttributes = {"cn", "sn", "givenName", "mail", "uid"};
        for (String valid : validAttributes) {
            if (valid.equals(attribute)) {
                return true;
            }
        }
        return false;
    }
}
// {/fact}