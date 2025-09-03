using System;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Web;
using System.Web.Mvc;
using System.Collections.Specialized;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;
using System.Security;
using System.Text;

namespace LdapInjectionExamples
{
    public class LdapInjectionController : Controller
    {
// {fact rule=ldap-injection@v1.0 defects=1}
        // True Positive Examples (Vulnerable Code)

        public void bad_case_1()
        {
            // Get username from HTTP request
            string username = Request.QueryString["username"];
            
            // Create LDAP directory entry
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldapServer");
            DirectorySearcher searcher = new DirectorySearcher(entry);
            
            // Vulnerable: Directly using user input in LDAP filter
            // ruleid: csharp-ldap-injection
            searcher.Filter = "(cn=" + username + ")";
            
            SearchResultCollection results = searcher.FindAll();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_2()
        {
            // Get user input from form post
            string userInput = Request.Form["department"];
            
            // Create LDAP connection
            DirectoryEntry directoryEntry = new DirectoryEntry("LDAP://ldap.example.com:389");
            DirectorySearcher searcher = new DirectorySearcher(directoryEntry);
            
            // Vulnerable: Concatenating user input directly into LDAP filter
            // ruleid: csharp-ldap-injection
            searcher.Filter = "(&(objectClass=user)(department=" + userInput + "))";
            
            searcher.FindAll();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_3()
        {
            // Get user input from HTTP header
            string userDN = Request.Headers["X-User-DN"];
            
            // Create LDAP connection with user input
            // ruleid: csharp-ldap-injection
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldapServer/" + userDN);
            
            // Use the entry to perform operations
            entry.Properties["mail"].Value = "new@example.com";
            entry.CommitChanges();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_4()
        {
            // Get multiple parameters from request
            string firstName = Request.QueryString["firstName"];
            string lastName = Request.QueryString["lastName"];
            
            // Create LDAP directory entry
            DirectoryEntry entry = new DirectoryEntry("LDAP://dc=example,dc=com");
            DirectorySearcher searcher = new DirectorySearcher(entry);
            
            // Vulnerable: Multiple user inputs concatenated into filter
            // ruleid: csharp-ldap-injection
            searcher.Filter = "(&(givenName=" + firstName + ")(sn=" + lastName + "))";
            
            SearchResultCollection results = searcher.FindAll();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

        public void bad_case_5()
        {
            // Get user input from cookie
            string group = Request.Cookies["preferredGroup"]?.Value;
            
            // Create LDAP connection
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldap.example.com");
            DirectorySearcher searcher = new DirectorySearcher(entry);
            
            // Vulnerable: Using cookie value in LDAP filter
            // ruleid: csharp-ldap-injection
            searcher.Filter = "(&(objectClass=group)(cn=" + group + "))";
            
            SearchResultCollection results = searcher.FindAll();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}
        
        [HttpPost]
        public ActionResult bad_case_6()
        {
            // Get user input from form
            string userId = Request.Form["userId"];
            
            // Create LDAP connection using System.DirectoryServices.Protocols
            LdapConnection connection = new LdapConnection(new LdapDirectoryIdentifier("ldap.example.com", 389));
            connection.Bind(new NetworkCredential("admin", "password", "domain"));
            
            // Vulnerable: Using user input in search filter
            SearchRequest searchRequest = new SearchRequest(
                "dc=example,dc=com",
                // ruleid: csharp-ldap-injection
                "(uid=" + userId + ")",
                System.DirectoryServices.Protocols.SearchScope.Subtree,
                null);
                
            SearchResponse response = (SearchResponse)connection.SendRequest(searchRequest);
            return View(response.Entries);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}
        
        public void bad_case_7()
        {
            // Get user input from URL path
            string orgUnit = RouteData.Values["orgUnit"] as string;
            
            // Create LDAP connection
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldap.example.com");
            DirectorySearcher searcher = new DirectorySearcher(entry);
            
            // Vulnerable: Using route data in LDAP filter
            // ruleid: csharp-ldap-injection
            searcher.Filter = "(&(objectClass=organizationalUnit)(ou=" + orgUnit + "))";
            
            SearchResultCollection results = searcher.FindAll();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}
        
        public void bad_case_8()
        {
            // Get multiple inputs and combine them
            string searchTerm = Request.QueryString["search"];
            string searchField = Request.QueryString["field"] ?? "cn";
            
            // Create LDAP connection
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldap.example.com");
            DirectorySearcher searcher = new DirectorySearcher(entry);
            
            // Vulnerable: Both field name and value come from user input
            // ruleid: csharp-ldap-injection
            searcher.Filter = "(&(objectClass=person)(" + searchField + "=" + searchTerm + "))";
            
            SearchResultCollection results = searcher.FindAll();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}
        
        [HttpGet]
        public void bad_case_9()
        {
            // Get user input from query string
            string email = Request.QueryString["email"];
            
            // Process the input (but not sanitizing it)
            string processedEmail = email.ToLower().Trim();
            
            // Create LDAP connection
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldap.example.com");
            DirectorySearcher searcher = new DirectorySearcher(entry);
            
            // Vulnerable: Processed but unsanitized input
            // ruleid: csharp-ldap-injection
            searcher.Filter = "(&(objectClass=user)(mail=" + processedEmail + "))";
            
            SearchResultCollection results = searcher.FindAll();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}
        
        public void bad_case_10()
        {
            // Get user input from form
            string role = Request.Form["role"];
            
            // Create LDAP connection
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldap.example.com");
            
            // Vulnerable: Using user input in path
            // ruleid: csharp-ldap-injection
            DirectoryEntry roleEntry = new DirectoryEntry("LDAP://ldap.example.com/cn=" + role + ",ou=roles,dc=example,dc=com");
            
            // Use the entry
            roleEntry.Properties["description"].Value = "Updated role";
            roleEntry.CommitChanges();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}
        
        public void bad_case_11()
        {
            // Get user input from JSON body (ASP.NET Core)
            var httpContext = HttpContext;
            string username = httpContext.Request.Form["username"];
            
            // Create LDAP connection
            using (var connection = new LdapConnection(new LdapDirectoryIdentifier("ldap.example.com")))
            {
                connection.Bind(new NetworkCredential("admin", "password"));
                
                // Vulnerable: Using user input in search filter
                var request = new SearchRequest(
                    "dc=example,dc=com",
                    // ruleid: csharp-ldap-injection
                    "(sAMAccountName=" + username + ")",
                    SearchScope.Subtree,
                    null);
                    
                connection.SendRequest(request);
            }
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}
        
        [HttpGet]
        public void bad_case_12()
        {
            // Get multiple parameters and build complex filter
            string dept = Request.QueryString["department"];
            string title = Request.QueryString["title"];
            
            // Create LDAP connection
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldap.example.com");
            DirectorySearcher searcher = new DirectorySearcher(entry);
            
            // Build complex filter with multiple inputs
            string filter = "(&(objectClass=user)";
            if (!string.IsNullOrEmpty(dept))
                filter += "(department=" + dept + ")";
            if (!string.IsNullOrEmpty(title))
                filter += "(title=" + title + ")";
            filter += ")";
            
            // Vulnerable: Complex filter with user inputs
            // ruleid: csharp-ldap-injection
            searcher.Filter = filter;
            
            SearchResultCollection results = searcher.FindAll();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}
        
        public void bad_case_13()
        {
            // Get user input from request
            string groupName = Request.QueryString["group"];
            
            // Create LDAP connection
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldap.example.com");
            
            try
            {
                // Vulnerable: Using user input in distinguished name
                // ruleid: csharp-ldap-injection
                string distinguishedName = "CN=" + groupName + ",OU=Groups,DC=example,DC=com";
                DirectoryEntry groupEntry = new DirectoryEntry("LDAP://ldap.example.com/" + distinguishedName);
                
                // Use the entry
                object nativeObject = groupEntry.NativeObject;
            }
            catch (Exception ex)
            {
                // Error handling
                Console.WriteLine(ex.Message);
            }
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}
        
        [HttpPost]
        public void bad_case_14()
        {
            // Get user input from form collection
            NameValueCollection form = Request.Form;
            string attribute = form["attribute"];
            string value = form["value"];
            
            // Create LDAP connection
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldap.example.com");
            DirectorySearcher searcher = new DirectorySearcher(entry);
            
            // Vulnerable: Both attribute name and value from user input
            // ruleid: csharp-ldap-injection
            searcher.Filter = "(&(objectClass=user)(" + attribute + "=" + value + "))";
            
            SearchResultCollection results = searcher.FindAll();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}
        
        public void bad_case_15()
        {
            // Get user input from query string
            string userFilter = Request.QueryString["filter"];
            
            if (!string.IsNullOrEmpty(userFilter))
            {
                // Create LDAP connection
                DirectoryEntry entry = new DirectoryEntry("LDAP://ldap.example.com");
                DirectorySearcher searcher = new DirectorySearcher(entry);
                
                // Vulnerable: Using entire filter from user input
                // ruleid: csharp-ldap-injection
                searcher.Filter = userFilter;
                
                SearchResultCollection results = searcher.FindAll();
            }
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}
        
        // True Negative Examples (Secure Code)
        
        public void good_case_1()
        {
            // Get username from HTTP request
            string username = Request.QueryString["username"];
            
            // Validate input using regex to ensure it only contains alphanumeric characters
            // ok: csharp-ldap-injection
            if (!Regex.IsMatch(username, "^[a-zA-Z0-9]+$"))
            {
                throw new ArgumentException("Username contains invalid characters");
            }
            
            // Create LDAP directory entry
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldapServer");
            DirectorySearcher searcher = new DirectorySearcher(entry);
            
            searcher.Filter = "(cn=" + username + ")";
            
            SearchResultCollection results = searcher.FindAll();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}
        
        public void good_case_2()
        {
            // Get user input from form post
            string userInput = Request.Form["department"];
            
            // Sanitize input by escaping special characters
            // ok: csharp-ldap-injection
            string sanitizedInput = EscapeLdapSearchFilter(userInput);
            
            // Create LDAP connection
            DirectoryEntry directoryEntry = new DirectoryEntry("LDAP://ldap.example.com:389");
            DirectorySearcher searcher = new DirectorySearcher(directoryEntry);
            
            searcher.Filter = "(&(objectClass=user)(department=" + sanitizedInput + "))";
            
            searcher.FindAll();
        }
// {/fact}
        
        // Helper method to escape LDAP special characters
        private string EscapeLdapSearchFilter(string filter)
        {
            if (string.IsNullOrEmpty(filter))
                return filter;
                
            StringBuilder sb = new StringBuilder();
            foreach (char c in filter)
            {
                switch (c)
                {
                    case '\\': sb.Append("\\5c"); break;
                    case '*': sb.Append("\\2a"); break;
                    case '(': sb.Append("\\28"); break;
                    case ')': sb.Append("\\29"); break;
                    case '\0': sb.Append("\\00"); break;
                    default: sb.Append(c); break;
                }
            }
            return sb.ToString();
        }
// {fact rule=ldap-injection@v1.0 defects=0}
        
        public void good_case_3()
        {
            // Get user input from HTTP header
            string userDN = Request.Headers["X-User-DN"];
            
            // Validate DN format using a whitelist approach
            // ok: csharp-ldap-injection
            if (!IsValidDistinguishedName(userDN))
            {
                throw new SecurityException("Invalid distinguished name format");
            }
            
            // Create LDAP connection with validated input
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldapServer/" + userDN);
            
            // Use the entry to perform operations
            entry.Properties["mail"].Value = "new@example.com";
            entry.CommitChanges();
        }
// {/fact}
        
        // Helper method to validate Distinguished Name format
        private bool IsValidDistinguishedName(string dn)
        {
            if (string.IsNullOrEmpty(dn))
                return false;
                
            // Check for valid DN format (simplified validation)
            return Regex.IsMatch(dn, @"^(?:(?:CN|OU|DC|O|C)=[^,]+,)*(?:CN|OU|DC|O|C)=[^,]+$", RegexOptions.IgnoreCase);
        }
// {fact rule=ldap-injection@v1.0 defects=0}
        
        public void good_case_4()
        {
            // Get multiple parameters from request
            string firstName = Request.QueryString["firstName"];
            string lastName = Request.QueryString["lastName"];
            
            // Create LDAP directory entry
            DirectoryEntry entry = new DirectoryEntry("LDAP://dc=example,dc=com");
            DirectorySearcher searcher = new DirectorySearcher(entry);
            
            // Use parameterized filter with proper escaping
            // ok: csharp-ldap-injection
            searcher.Filter = string.Format("(&(givenName={0})(sn={1}))", 
                EscapeLdapSearchFilter(firstName), 
                EscapeLdapSearchFilter(lastName));
            
            SearchResultCollection results = searcher.FindAll();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}
        
        public void good_case_5()
        {
            // Get user input from cookie
            string group = Request.Cookies["preferredGroup"]?.Value;
            
            // Whitelist validation - only allow specific group values
            // ok: csharp-ldap-injection
            string[] allowedGroups = { "Admins", "Users", "Guests", "Support" };
            if (!Array.Exists(allowedGroups, g => g == group))
            {
                throw new SecurityException("Invalid group specified");
            }
            
            // Create LDAP connection
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldap.example.com");
            DirectorySearcher searcher = new DirectorySearcher(entry);
            
            searcher.Filter = "(&(objectClass=group)(cn=" + group + "))";
            
            SearchResultCollection results = searcher.FindAll();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}
        
        [HttpPost]
        public ActionResult good_case_6()
        {
            // Get user input from form
            string userId = Request.Form["userId"];
            
            // Sanitize input by removing special characters
            // ok: csharp-ldap-injection
            string sanitizedUserId = Regex.Replace(userId, "[^a-zA-Z0-9_-]", "");
            
            // Create LDAP connection using System.DirectoryServices.Protocols
            LdapConnection connection = new LdapConnection(new LdapDirectoryIdentifier("ldap.example.com", 389));
            connection.Bind(new NetworkCredential("admin", "password", "domain"));
            
            // Use sanitized input in search filter
            SearchRequest searchRequest = new SearchRequest(
                "dc=example,dc=com",
                "(uid=" + sanitizedUserId + ")",
                System.DirectoryServices.Protocols.SearchScope.Subtree,
                null);
                
            SearchResponse response = (SearchResponse)connection.SendRequest(searchRequest);
            return View(response.Entries);
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}
        
        public void good_case_7()
        {
            // Get user input from URL path
            string orgUnit = RouteData.Values["orgUnit"] as string;
            
            // Validate length and character set
            // ok: csharp-ldap-injection
            if (string.IsNullOrEmpty(orgUnit) || orgUnit.Length > 50 || !Regex.IsMatch(orgUnit, "^[a-zA-Z0-9\\s-]+$"))
            {
                throw new ArgumentException("Invalid organizational unit name");
            }
            
            // Create LDAP connection
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldap.example.com");
            DirectorySearcher searcher = new DirectorySearcher(entry);
            
            searcher.Filter = "(&(objectClass=organizationalUnit)(ou=" + orgUnit + "))";
            
            SearchResultCollection results = searcher.FindAll();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}
        
        public void good_case_8()
        {
            // Get multiple inputs and combine them
            string searchTerm = Request.QueryString["search"];
            string searchField = Request.QueryString["field"] ?? "cn";
            
            // Validate field name against whitelist
            // ok: csharp-ldap-injection
            string[] allowedFields = { "cn", "givenName", "sn", "mail", "employeeID" };
            if (!Array.Exists(allowedFields, f => f == searchField))
            {
                searchField = "cn"; // Default to a safe value
            }
            
            // Escape the search term
            string escapedSearchTerm = EscapeLdapSearchFilter(searchTerm);
            
            // Create LDAP connection
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldap.example.com");
            DirectorySearcher searcher = new DirectorySearcher(entry);
            
            searcher.Filter = "(&(objectClass=person)(" + searchField + "=" + escapedSearchTerm + "))";
            
            SearchResultCollection results = searcher.FindAll();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}
        
        [HttpGet]
        public void good_case_9()
        {
            // Get user input from query string
            string email = Request.QueryString["email"];
            
            // Validate email format
            // ok: csharp-ldap-injection
            if (!Regex.IsMatch(email, @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"))
            {
                throw new ArgumentException("Invalid email format");
            }
            
            // Escape special characters
            string escapedEmail = EscapeLdapSearchFilter(email);
            
            // Create LDAP connection
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldap.example.com");
            DirectorySearcher searcher = new DirectorySearcher(entry);
            
            searcher.Filter = "(&(objectClass=user)(mail=" + escapedEmail + "))";
            
            SearchResultCollection results = searcher.FindAll();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}
        
        public void good_case_10()
        {
            // Get user input from form
            string role = Request.Form["role"];
            
            // Use a mapping approach instead of direct input
            // ok: csharp-ldap-injection
            Dictionary<string, string> roleDNMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "admin", "cn=Administrators,ou=roles,dc=example,dc=com" },
                { "user", "cn=Users,ou=roles,dc=example,dc=com" },
                { "guest", "cn=Guests,ou=roles,dc=example,dc=com" }
            };
            
            if (!roleDNMap.TryGetValue(role, out string roleDN))
            {
                throw new ArgumentException("Invalid role specified");
            }
            
            // Create LDAP connection with mapped value
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldap.example.com/" + roleDN);
            
            // Use the entry
            entry.Properties["description"].Value = "Updated role";
            entry.CommitChanges();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}
        
        public void good_case_11()
        {
            // Get user input from JSON body (ASP.NET Core)
            var httpContext = HttpContext;
            string username = httpContext.Request.Form["username"];
            
            // Validate username format and length
            // ok: csharp-ldap-injection
            if (string.IsNullOrEmpty(username) || username.Length > 50 || 
                !Regex.IsMatch(username, "^[a-zA-Z0-9._-]+$"))
            {
                throw new ArgumentException("Invalid username format");
            }
            
            // Create LDAP connection
            using (var connection = new LdapConnection(new LdapDirectoryIdentifier("ldap.example.com")))
            {
                connection.Bind(new NetworkCredential("admin", "password"));
                
                var request = new SearchRequest(
                    "dc=example,dc=com",
                    "(sAMAccountName=" + username + ")",
                    SearchScope.Subtree,
                    null);
                    
                connection.SendRequest(request);
            }
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}
        
        [HttpGet]
        public void good_case_12()
        {
            // Get multiple parameters and build complex filter
            string dept = Request.QueryString["department"];
            string title = Request.QueryString["title"];
            
            // Create LDAP connection
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldap.example.com");
            DirectorySearcher searcher = new DirectorySearcher(entry);
            
            // Build complex filter with proper escaping
            // ok: csharp-ldap-injection
            StringBuilder filterBuilder = new StringBuilder("(&(objectClass=user)");
            if (!string.IsNullOrEmpty(dept))
                filterBuilder.Append("(department=" + EscapeLdapSearchFilter(dept) + ")");
            if (!string.IsNullOrEmpty(title))
                filterBuilder.Append("(title=" + EscapeLdapSearchFilter(title) + ")");
            filterBuilder.Append(")");
            
            searcher.Filter = filterBuilder.ToString();
            
            SearchResultCollection results = searcher.FindAll();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}
        
        public void good_case_13()
        {
            // Get user input from request
            string groupName = Request.QueryString["group"];
            
            // Create LDAP connection
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldap.example.com");
            
            try
            {
                // Validate group name format
                // ok: csharp-ldap-injection
                if (!Regex.IsMatch(groupName, "^[a-zA-Z0-9\\s-]+$") || groupName.Length > 50)
                {
                    throw new ArgumentException("Invalid group name format");
                }
                
                string distinguishedName = "CN=" + EscapeLdapSearchFilter(groupName) + ",OU=Groups,DC=example,DC=com";
                DirectoryEntry groupEntry = new DirectoryEntry("LDAP://ldap.example.com/" + distinguishedName);
                
                // Use the entry
                object nativeObject = groupEntry.NativeObject;
            }
            catch (Exception ex)
            {
                // Error handling
                Console.WriteLine(ex.Message);
            }
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}
        
        [HttpPost]
        public void good_case_14()
        {
            // Get user input from form collection
            NameValueCollection form = Request.Form;
            string attribute = form["attribute"];
            string value = form["value"];
            
            // Validate attribute against whitelist
            // ok: csharp-ldap-injection
            string[] allowedAttributes = { "cn", "givenName", "sn", "mail", "telephoneNumber", "title" };
            if (!Array.Exists(allowedAttributes, a => a == attribute))
            {
                throw new ArgumentException("Invalid attribute name");
            }
            
            // Escape the value
            string escapedValue = EscapeLdapSearchFilter(value);
            
            // Create LDAP connection
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldap.example.com");
            DirectorySearcher searcher = new DirectorySearcher(entry);
            
            searcher.Filter = "(&(objectClass=user)(" + attribute + "=" + escapedValue + "))";
            
            SearchResultCollection results = searcher.FindAll();
        }
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}
        
        public void good_case_15()
        {
            // Instead of accepting a full filter from user input,
            // use a predefined filter template with placeholders
            string searchTerm = Request.QueryString["search"];
            
            // ok: csharp-ldap-injection
            string escapedSearchTerm = EscapeLdapSearchFilter(searchTerm);
            
            // Create LDAP connection
            DirectoryEntry entry = new DirectoryEntry("LDAP://ldap.example.com");
            DirectorySearcher searcher = new DirectorySearcher(entry);
            
            // Use a predefined filter template with the sanitized input
            searcher.Filter = string.Format("(&(objectClass=user)(|(cn=*{0}*)(mail=*{0}*)(sn=*{0}*)))", 
                escapedSearchTerm);
            
            SearchResultCollection results = searcher.FindAll();
        }
// {/fact}
    }
}