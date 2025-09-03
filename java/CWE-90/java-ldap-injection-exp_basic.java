import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.util.Hashtable;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.InitialLdapContext;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import java.util.regex.Pattern;
import org.owasp.esapi.ESAPI;
import org.apache.commons.text.StringEscapeUtils;

@Controller
public class LdapInjectionExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=ldap-injection@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) {
        try {
            String username = request.getParameter("username");
            
            DirContext ctx = new InitialDirContext();
            String searchFilter = "(uid=" + username + ")";
            
            // ruleid: java-ldap-injection-exp
            NamingEnumeration<SearchResult> results = ctx.search("ou=users,dc=example,dc=com", 
                                                               searchFilter, 
                                                               new SearchControls());
            
            while (results.hasMore()) {
                SearchResult result = results.next();
                response.getWriter().println(result.getNameInNamespace());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) {
        try {
            String userInput = request.getParameter("group");
            
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            DirContext ctx = new InitialDirContext(env);
            
            String filter = "(&(objectClass=group)(cn=" + userInput + "))";
            SearchControls ctls = new SearchControls();
            ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            // ruleid: java-ldap-injection-exp
            NamingEnumeration<SearchResult> answer = ctx.search("dc=example,dc=com", filter, ctls);
            
            while (answer.hasMoreElements()) {
                SearchResult sr = answer.next();
                response.getWriter().println(sr.getName());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @GetMapping("/ldap/search")
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) {
        try {
            String email = request.getParameter("email");
            
            DirContext ctx = new InitialDirContext();
            String searchBase = "ou=users,dc=example,dc=com";
            String searchFilter = "(mail=" + email + ")";
            
            // ruleid: java-ldap-injection-exp
            NamingEnumeration<SearchResult> results = ctx.search(searchBase, searchFilter, null);
            
            while (results.hasMore()) {
                response.getWriter().println(results.next().toString());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) {
        try {
            String lastName = request.getParameter("lastName");
            String firstName = request.getParameter("firstName");
            
            DirContext ctx = new InitialDirContext();
            String filter = "(&(sn=" + lastName + ")(givenName=" + firstName + "))";
            
            // ruleid: java-ldap-injection-exp
            ctx.search("ou=people,dc=example,dc=com", filter, new SearchControls());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @PostMapping("/ldap/authenticate")
    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) {
        try {
            String username = request.getParameter("username");
            String password = request.getParameter("password");
            
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            
            String filter = "(uid=" + username + ")";
            env.put(Context.SECURITY_PRINCIPAL, "cn=admin,dc=example,dc=com");
            env.put(Context.SECURITY_CREDENTIALS, "adminPassword");
            
            DirContext ctx = new InitialDirContext(env);
            SearchControls ctls = new SearchControls();
            
            // ruleid: java-ldap-injection-exp
            NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", filter, ctls);
            
            if (results.hasMore()) {
                response.getWriter().println("User found");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @RequestMapping("/ldap/find")
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) {
        try {
            String department = request.getParameter("department");
            String role = request.getHeader("X-Role");
            
            DirContext ctx = new InitialDirContext();
            String filter = "(&(department=" + department + ")(role=" + role + "))";
            
            // ruleid: java-ldap-injection-exp
            NamingEnumeration<SearchResult> results = ctx.search("ou=employees,dc=example,dc=com", filter, null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) {
        try {
            String phoneNumber = request.getParameter("phone");
            
            Hashtable<String, Object> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://directory.example.com:389");
            
            LdapContext ctx = new InitialLdapContext(env, null);
            SearchControls ctls = new SearchControls();
            ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            String filter = "(telephoneNumber=" + phoneNumber + ")";
            
            // ruleid: java-ldap-injection-exp
            NamingEnumeration<SearchResult> answer = ctx.search("ou=contacts,dc=example,dc=com", filter, ctls);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @GetMapping("/ldap/manager")
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) {
        try {
            String employeeId = request.getParameter("id");
            
            DirContext ctx = new InitialDirContext();
            
            // Constructing filter with concatenation
            String filter = "(employeeID=" + employeeId + ")";
            
            // ruleid: java-ldap-injection-exp
            NamingEnumeration<SearchResult> results = ctx.search("ou=employees,dc=example,dc=com", filter, new SearchControls());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) {
        try {
            String groupName = request.getParameter("group");
            String memberAttr = request.getParameter("memberAttr");
            
            DirContext ctx = new InitialDirContext();
            
            // Multiple user inputs in filter
            String filter = "(&(objectClass=group)(cn=" + groupName + ")(" + memberAttr + "=*))";
            
            // ruleid: java-ldap-injection-exp
            ctx.search("dc=example,dc=com", filter, new SearchControls());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @PostMapping("/ldap/query")
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Using StringBuilder to construct filter
            StringBuilder filterBuilder = new StringBuilder("(objectClass=person)");
            
            String name = request.getParameter("name");
            if (name != null && !name.isEmpty()) {
                filterBuilder.append("(cn=").append(name).append(")");
            }
            
            DirContext ctx = new InitialDirContext();
            String filter = filterBuilder.toString();
            
            // ruleid: java-ldap-injection-exp
            NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", filter, null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) {
        try {
            String userDN = "cn=" + request.getParameter("username") + ",ou=users,dc=example,dc=com";
            
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, userDN);
            env.put(Context.SECURITY_CREDENTIALS, "password");
            
            // ruleid: java-ldap-injection-exp
            DirContext ctx = new InitialDirContext(env);
            // Using tainted DN for authentication
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @GetMapping("/ldap/search/complex")
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) {
        try {
            String searchTerm = request.getParameter("q");
            String searchType = request.getParameter("type");
            
            DirContext ctx = new InitialDirContext();
            
            String filter;
            if ("name".equals(searchType)) {
                filter = "(cn=*" + searchTerm + "*)";
            } else if ("email".equals(searchType)) {
                filter = "(mail=*" + searchTerm + "*)";
            } else {
                filter = "(description=*" + searchTerm + "*)";
            }
            
            // ruleid: java-ldap-injection-exp
            NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", filter, new SearchControls());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Indirect taint flow
            String userId = request.getParameter("uid");
            String query = userId;
            
            if (query.length() > 10) {
                query = query.substring(0, 10);
            }
            
            DirContext ctx = new InitialDirContext();
            String filter = "(uid=" + query + ")";
            
            // ruleid: java-ldap-injection-exp
            NamingEnumeration<SearchResult> results = ctx.search("ou=users,dc=example,dc=com", filter, null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @RequestMapping("/ldap/search/attributes")
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) {
        try {
            String attrName = request.getParameter("attr");
            String attrValue = request.getParameter("value");
            
            DirContext ctx = new InitialDirContext();
            
            // Tainted attribute name in filter
            String filter = "(" + attrName + "=" + attrValue + ")";
            
            // ruleid: java-ldap-injection-exp
            ctx.search("dc=example,dc=com", filter, new SearchControls());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Complex string manipulation but still vulnerable
            String input = request.getParameter("title");
            String processedInput = input.toUpperCase().replace(" ", "_");
            
            DirContext ctx = new InitialDirContext();
            String filter = "(title=" + processedInput + ")";
            
            // ruleid: java-ldap-injection-exp
            NamingEnumeration<SearchResult> results = ctx.search("ou=jobs,dc=example,dc=com", filter, new SearchControls());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Safe Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) {
        try {
            String username = request.getParameter("username");
            
            // Escape LDAP special characters
            // ok: java-ldap-injection-exp
            username = StringEscapeUtils.escapeJava(username);
            
            DirContext ctx = new InitialDirContext();
            String searchFilter = "(uid=" + username + ")";
            
            NamingEnumeration<SearchResult> results = ctx.search("ou=users,dc=example,dc=com", 
                                                               searchFilter, 
                                                               new SearchControls());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) {
        try {
            String userInput = request.getParameter("group");
            
            // Validate input against whitelist
            // ok: java-ldap-injection-exp
            if (!Pattern.matches("[a-zA-Z0-9_-]+", userInput)) {
                throw new IllegalArgumentException("Invalid group name");
            }
            
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            DirContext ctx = new InitialDirContext(env);
            
            String filter = "(&(objectClass=group)(cn=" + userInput + "))";
            SearchControls ctls = new SearchControls();
            ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            NamingEnumeration<SearchResult> answer = ctx.search("dc=example,dc=com", filter, ctls);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @GetMapping("/ldap/search/safe")
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) {
        try {
            String email = request.getParameter("email");
            
            // Using ESAPI for proper escaping
            // ok: java-ldap-injection-exp
            email = ESAPI.encoder().encodeForLDAP(email);
            
            DirContext ctx = new InitialDirContext();
            String searchBase = "ou=users,dc=example,dc=com";
            String searchFilter = "(mail=" + email + ")";
            
            NamingEnumeration<SearchResult> results = ctx.search(searchBase, searchFilter, null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_4(HttpServletRequest request, HttpServletResponse response) {
        try {
            String lastName = request.getParameter("lastName");
            String firstName = request.getParameter("firstName");
            
            // Custom LDAP escaping function
            // ok: java-ldap-injection-exp
            lastName = escapeLDAPSearchFilter(lastName);
            firstName = escapeLDAPSearchFilter(firstName);
            
            DirContext ctx = new InitialDirContext();
            String filter = "(&(sn=" + lastName + ")(givenName=" + firstName + "))";
            
            ctx.search("ou=people,dc=example,dc=com", filter, new SearchControls());
        } catch (Exception e) {
            e.printStackTrace();
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
                case '\\': sb.append("\\5c"); break;
                case '*': sb.append("\\2a"); break;
                case '(': sb.append("\\28"); break;
                case ')': sb.append("\\29"); break;
                case '\u0000': sb.append("\\00"); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }

    @PostMapping("/ldap/authenticate/safe")
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) {
        try {
            String username = request.getParameter("username");
            
            // Using parameterized search with javax.naming.directory.Attributes
            // ok: java-ldap-injection-exp
            javax.naming.directory.Attributes matchAttrs = new javax.naming.directory.BasicAttributes(true);
            matchAttrs.put(new javax.naming.directory.BasicAttribute("uid", username));
            
            DirContext ctx = new InitialDirContext();
            NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", matchAttrs);
            
            if (results.hasMore()) {
                response.getWriter().println("User found");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @RequestMapping("/ldap/find/safe")
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) {
        try {
            String department = request.getParameter("department");
            String role = request.getHeader("X-Role");
            
            // Whitelist validation
            // ok: java-ldap-injection-exp
            if (!isValidDepartment(department) || !isValidRole(role)) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid input");
                return;
            }
            
            DirContext ctx = new InitialDirContext();
            String filter = "(&(department=" + department + ")(role=" + role + "))";
            
            NamingEnumeration<SearchResult> results = ctx.search("ou=employees,dc=example,dc=com", filter, null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private boolean isValidDepartment(String department) {
        String[] validDepartments = {"IT", "HR", "Finance", "Marketing", "Sales"};
        for (String valid : validDepartments) {
            if (valid.equals(department)) {
                return true;
            }
        }
        return false;
    }
    
    private boolean isValidRole(String role) {
        String[] validRoles = {"Admin", "User", "Manager", "Developer"};
        for (String valid : validRoles) {
            if (valid.equals(role)) {
                return true;
            }
        }
        return false;
    }

    public void good_case_7(HttpServletRequest request, HttpServletResponse response) {
        try {
            String phoneNumber = request.getParameter("phone");
            
            // Input validation with regex
            // ok: java-ldap-injection-exp
            if (!phoneNumber.matches("^[0-9+\\-\\s]+$")) {
                throw new IllegalArgumentException("Invalid phone number format");
            }
            
            Hashtable<String, Object> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://directory.example.com:389");
            
            LdapContext ctx = new InitialLdapContext(env, null);
            SearchControls ctls = new SearchControls();
            ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            String filter = "(telephoneNumber=" + phoneNumber + ")";
            
            NamingEnumeration<SearchResult> answer = ctx.search("ou=contacts,dc=example,dc=com", filter, ctls);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @GetMapping("/ldap/manager/safe")
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) {
        try {
            String employeeId = request.getParameter("id");
            
            // Using prepared filter with placeholders
            // ok: java-ldap-injection-exp
            String filterTemplate = "(employeeID={0})";
            Object[] filterArgs = new Object[]{employeeId};
            
            DirContext ctx = new InitialDirContext();
            
            // Using search with filter arguments
            NamingEnumeration<SearchResult> results = ctx.search(
                "ou=employees,dc=example,dc=com", 
                filterTemplate, 
                filterArgs,
                new SearchControls()
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9(HttpServletRequest request, HttpServletResponse response) {
        try {
            String groupName = request.getParameter("group");
            
            // Comprehensive LDAP special character escaping
            // ok: java-ldap-injection-exp
            groupName = groupName.replace("\\", "\\5c")
                                .replace("*", "\\2a")
                                .replace("(", "\\28")
                                .replace(")", "\\29")
                                .replace("\u0000", "\\00");
            
            DirContext ctx = new InitialDirContext();
            String filter = "(&(objectClass=group)(cn=" + groupName + "))";
            
            ctx.search("dc=example,dc=com", filter, new SearchControls());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @PostMapping("/ldap/query/safe")
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Using javax.naming.directory.Attributes for safe search
            // ok: java-ldap-injection-exp
            javax.naming.directory.Attributes searchAttrs = new javax.naming.directory.BasicAttributes();
            
            String name = request.getParameter("name");
            if (name != null && !name.isEmpty()) {
                searchAttrs.put(new javax.naming.directory.BasicAttribute("cn", name));
            }
            
            searchAttrs.put(new javax.naming.directory.BasicAttribute("objectClass", "person"));
            
            DirContext ctx = new InitialDirContext();
            NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", searchAttrs);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11(HttpServletRequest request, HttpServletResponse response) {
        try {
            String username = request.getParameter("username");
            
            // Validate username format before using in DN
            // ok: java-ldap-injection-exp
            if (!username.matches("^[a-zA-Z0-9._-]{3,20}$")) {
                throw new IllegalArgumentException("Invalid username format");
            }
            
            String userDN = "cn=" + username + ",ou=users,dc=example,dc=com";
            
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FAC_REDACTED_TWILIO_ID, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, userDN);
            env.put(Context.SECURITY_CREDENTIALS, "password");
            
            DirContext ctx = new InitialDirContext(env);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @GetMapping("/ldap/search/complex/safe")
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) {
        try {
            String searchTerm = request.getParameter("q");
            String searchType = request.getParameter("type");
            
            // Escape search term
            // ok: java-ldap-injection-exp
            searchTerm = ESAPI.encoder().encodeForLDAP(searchTerm);
            
            // Validate search type against whitelist
            if (!Arrays.asList("name", "email", "description").contains(searchType)) {
                searchType = "name"; // Default to safe value
            }
            
            DirContext ctx = new InitialDirContext();
            
            String filter;
            if ("name".equals(searchType)) {
                filter = "(cn=*" + searchTerm + "*)";
            } else if ("email".equals(searchType)) {
                filter = "(mail=*" + searchTerm + "*)";
            } else {
                filter = "(description=*" + searchTerm + "*)";
            }
            
            NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", filter, new SearchControls());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Using parameterized search with javax.naming.directory.Attributes
            // ok: java-ldap-injection-exp
            String userId = request.getParameter("uid");
            
            javax.naming.directory.SearchControls searchControls = new javax.naming.directory.SearchControls();
            searchControls.setSearchScope(javax.naming.directory.SearchControls.SUBTREE_SCOPE);
            
            String filterExpr = "(uid={0})";
            Object[] filterArgs = new Object[]{userId};
            
            DirContext ctx = new InitialDirContext();
            NamingEnumeration<SearchResult> results = ctx.search(
                "ou=users,dc=example,dc=com", 
                filterExpr, 
                filterArgs, 
                searchControls
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @RequestMapping("/ldap/search/attributes/safe")
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) {
        try {
            String attrValue = request.getParameter("value");
            String attrName = request.getParameter("attr");
            
            // Whitelist validation for attribute name
            // ok: java-ldap-injection-exp
            String[] allowedAttrs = {"cn", "mail", "sn", "givenName", "uid"};
            boolean validAttr = false;
            
            for (String allowed : allowedAttrs) {
                if (allowed.equals(attrName)) {
                    validAttr = true;
                    break;
                }
            }
            
            if (!validAttr) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid attribute");
                return;
            }
            
            // Escape attribute value
            attrValue = escapeLDAPSearchFilter(attrValue);
            
            DirContext ctx = new InitialDirContext();
            String filter = "(" + attrName + "=" + attrValue + ")";
            
            ctx.search("dc=example,dc=com", filter, new SearchControls());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Using a prepared filter with placeholders and arguments
            // ok: java-ldap-injection-exp
            String input = request.getParameter("title");
            
            DirContext ctx = new InitialDirContext();
            
            String filterTemplate = "(title={0})";
            Object[] filterArgs = new Object[]{input.toUpperCase().replace(" ", "_")};
            
            NamingEnumeration<SearchResult> results = ctx.search(
                "ou=jobs,dc=example,dc=com", 
                filterTemplate, 
                filterArgs, 
                new SearchControls()
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}