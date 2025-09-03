using System;
using System.Xml;
using System.Web;
using System.Web.Mvc;
using System.Net.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.IO;
using System.Text;
using System.Security;
using System.Xml.XPath;

namespace XPathInjectionExamples
{
    public class XPathInjectionController : Controller
    {
// {fact rule=xpath-injection@v1.0 defects=1}
        // True Positive Examples (Vulnerable Code)

        public ActionResult bad_case_1()
        {
            // Get user input directly from request
            string username = Request.QueryString["username"];
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("users.xml");
            XPathNavigator navigator = xmlDoc.CreateNavigator();
            
            // Directly using user input in XPath query
            // ruleid: xpath-injection-charp-rule
            string query = "//users/user[username='" + username + "']";
            XPathNodeIterator nodes = navigator.Select(query);
            
            return View(nodes);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=1}

        public ActionResult bad_case_2()
        {
            // Get user input from form
            string userId = Request.Form["userId"];
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("employees.xml");
            
            // Concatenating user input directly into XPath expression
            // ruleid: xpath-injection-charp-rule
            XmlNodeList nodeList = xmlDoc.SelectNodes("/employees/employee[@id='" + userId + "']");
            
            return View(nodeList);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=1}

        [HttpGet]
        public ActionResult bad_case_3()
        {
            // Get user input from route parameter
            string department = RouteData.Values["department"].ToString();
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("organization.xml");
            
            // Using user input in XPath without sanitization
            // ruleid: xpath-injection-charp-rule
            string xpathQuery = "//organization/department[@name='" + department + "']/employees";
            XmlNodeList employees = xmlDoc.SelectNodes(xpathQuery);
            
            return View(employees);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=1}

        public ActionResult bad_case_4()
        {
            // Get user input from cookie
            string role = Request.Cookies["role"].Value;
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml("<permissions><role name='admin'><access>full</access></role><role name='user'><access>limited</access></role></permissions>");
            
            // Using cookie value directly in XPath
            // ruleid: xpath-injection-charp-rule
            XmlNode roleNode = xmlDoc.SelectSingleNode("/permissions/role[@name='" + role + "']");
            
            return Content(roleNode?.InnerXml ?? "Role not found");
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=1}

        [HttpPost]
        public ActionResult bad_case_5()
        {
            // Get multiple parameters and use them in XPath
            string firstName = Request.Form["firstName"];
            string lastName = Request.Form["lastName"];
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("customers.xml");
            
            // Multiple user inputs used unsafely
            // ruleid: xpath-injection-charp-rule
            string xpathQuery = "//customers/customer[firstName='" + firstName + "' and lastName='" + lastName + "']";
            XmlNode customer = xmlDoc.SelectSingleNode(xpathQuery);
            
            return View(customer);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=1}

        public ActionResult bad_case_6(HttpRequestMessage request)
        {
            // Get user input from header
            string category = request.Headers.GetValues("X-Category").FirstOrDefault();
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("products.xml");
            
            // Using header value in XPath
            // ruleid: xpath-injection-charp-rule
            XmlNodeList products = xmlDoc.SelectNodes("/products/product[category='" + category + "']");
            
            return View(products);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=1}

        [HttpGet]
        public ActionResult bad_case_7()
        {
            // Get user input from query string with minimal processing
            string searchTerm = Request.QueryString["search"].ToLower();
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("articles.xml");
            
            // Processing the input doesn't make it safe
            // ruleid: xpath-injection-charp-rule
            string xpathQuery = "//articles/article[contains(translate(title,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'" + searchTerm + "')]";
            XmlNodeList articles = xmlDoc.SelectNodes(xpathQuery);
            
            return View(articles);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=1}

        public ActionResult bad_case_8()
        {
            // Get user input from multiple sources
            string tag = Request.QueryString["tag"];
            string author = Request.Form["author"];
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("blog.xml");
            
            // Combining multiple inputs unsafely
            // ruleid: xpath-injection-charp-rule
            XmlNodeList posts = xmlDoc.SelectNodes("//blog/post[tags/tag='" + tag + "' and author='" + author + "']");
            
            return View(posts);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=1}

        [HttpPost]
        public ActionResult bad_case_9()
        {
            // Get JSON data from request body
            var reader = new StreamReader(Request.InputStream);
            string requestBody = reader.ReadToEnd();
            dynamic data = Newtonsoft.Json.JsonConvert.DeserializeObject(requestBody);
            string productId = data.productId;
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("inventory.xml");
            
            // Using input from JSON body in XPath
            // ruleid: xpath-injection-charp-rule
            XmlNode product = xmlDoc.SelectSingleNode("/inventory/product[@id='" + productId + "']");
            
            return Json(product != null);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=1}

        public ActionResult bad_case_10(HttpContext context)
        {
            // Get user input from query parameter
            string attribute = context.Request.Query["attribute"];
            string value = context.Request.Query["value"];
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("data.xml");
            
            // Dynamic attribute name in XPath query
            // ruleid: xpath-injection-charp-rule
            string xpathQuery = "//data/item[@" + attribute + "='" + value + "']";
            XmlNodeList items = xmlDoc.SelectNodes(xpathQuery);
            
            return new JsonResult(items);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=1}

        [HttpGet]
        public ActionResult bad_case_11()
        {
            // Get user input and do minimal validation
            string year = Request.QueryString["year"];
            if (year.Length != 4) // Simple validation doesn't prevent injection
            {
                return Content("Invalid year format");
            }
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("records.xml");
            
            // Simple validation is insufficient
            // ruleid: xpath-injection-charp-rule
            XmlNodeList records = xmlDoc.SelectNodes("//records/record[year='" + year + "']");
            
            return View(records);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=1}

        public ActionResult bad_case_12()
        {
            // Get user input from referer header
            string referer = Request.Headers["Referer"];
            string source = HttpUtility.ParseQueryString(new Uri(referer).Query).Get("source");
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("referrals.xml");
            
            // Using parsed referer data in XPath
            // ruleid: xpath-injection-charp-rule
            XmlNode referralInfo = xmlDoc.SelectSingleNode("//referrals/referral[@source='" + source + "']");
            
            return View(referralInfo);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=1}

        [HttpPost]
        public ActionResult bad_case_13()
        {
            // Get user input from multipart form
            HttpPostedFile file = Request.Files["config"];
            string configName = Path.GetFileNameWithoutExtension(file.FileName);
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("configurations.xml");
            
            // Using filename in XPath query
            // ruleid: xpath-injection-charp-rule
            XmlNode configNode = xmlDoc.SelectSingleNode("//configurations/config[@name='" + configName + "']");
            
            return View(configNode);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=1}

        public ActionResult bad_case_14()
        {
            // Get user input and attempt to escape it (incorrectly)
            string username = Request.QueryString["username"].Replace("'", "''"); // SQL-style escaping doesn't work for XPath
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("users.xml");
            
            // Incorrect escaping method
            // ruleid: xpath-injection-charp-rule
            XmlNodeList users = xmlDoc.SelectNodes("//users/user[username='" + username + "']");
            
            return View(users);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=1}

        [HttpGet]
        public ActionResult bad_case_15()
        {
            // Get user input from URL fragment
            string fragment = Request.Url.Fragment;
            if (!string.IsNullOrEmpty(fragment))
            {
                fragment = fragment.Substring(1); // Remove the # character
            }
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("sections.xml");
            
            // Using URL fragment in XPath
            // ruleid: xpath-injection-charp-rule
            XmlNode section = xmlDoc.SelectSingleNode("//document/section[@id='" + fragment + "']");
            
            return View(section);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=0}

        // True Negative Examples (Safe Code)

        public ActionResult good_case_1()
        {
            // Get user input
            string username = Request.QueryString["username"];
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("users.xml");
            
            // Using XPath parameters to prevent injection
            XPathNavigator navigator = xmlDoc.CreateNavigator();
            XPathExpression expr = navigator.Compile("//users/user[username=$username]");
            
            // ok: xpath-injection-charp-rule
            XPathNodeIterator nodes = navigator.Select(expr);
            
            return View(nodes);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=0}

        public ActionResult good_case_2()
        {
            // Get user input from form
            string userId = Request.Form["userId"];
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("employees.xml");
            
            // Using XPathNavigator with parameters
            XPathNavigator navigator = xmlDoc.CreateNavigator();
            XPathExpression expr = navigator.Compile("/employees/employee[@id=$userId]");
            
            XsltArgumentList args = new XsltArgumentList();
            args.AddParam("userId", "", userId);
            
            // ok: xpath-injection-charp-rule
            XPathNodeIterator iterator = navigator.Select(expr, args);
            
            return View(iterator);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=0}

        [HttpGet]
        public ActionResult good_case_3()
        {
            // Get user input from route parameter
            string department = RouteData.Values["department"].ToString();
            
            // Validate against a whitelist
            string[] validDepartments = { "HR", "IT", "Finance", "Marketing", "Sales" };
            if (!validDepartments.Contains(department))
            {
                return Content("Invalid department");
            }
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("organization.xml");
            
            // ok: xpath-injection-charp-rule
            string xpathQuery = "//organization/department[@name='" + department + "']/employees";
            XmlNodeList employees = xmlDoc.SelectNodes(xpathQuery);
            
            return View(employees);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=0}

        public ActionResult good_case_4()
        {
            // Get user input from cookie
            string role = Request.Cookies["role"]?.Value;
            
            // Validate input against enum/whitelist
            if (!Enum.TryParse<UserRole>(role, true, out UserRole validRole))
            {
                return Content("Invalid role");
            }
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml("<permissions><role name='admin'><access>full</access></role><role name='user'><access>limited</access></role></permissions>");
            
            // ok: xpath-injection-charp-rule
            XmlNode roleNode = xmlDoc.SelectSingleNode($"/permissions/role[@name='{validRole.ToString().ToLower()}']");
            
            return Content(roleNode?.InnerXml ?? "Role not found");
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=0}

        [HttpPost]
        public ActionResult good_case_5()
        {
            // Get multiple parameters
            string firstName = Request.Form["firstName"];
            string lastName = Request.Form["lastName"];
            
            // Sanitize inputs using SecurityElement.Escape
            string safeFirstName = SecurityElement.Escape(firstName);
            string safeLastName = SecurityElement.Escape(lastName);
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("customers.xml");
            
            // ok: xpath-injection-charp-rule
            string xpathQuery = "//customers/customer[firstName='" + safeFirstName + "' and lastName='" + safeLastName + "']";
            XmlNode customer = xmlDoc.SelectSingleNode(xpathQuery);
            
            return View(customer);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=0}

        public ActionResult good_case_6(HttpRequestMessage request)
        {
            // Get user input from header
            string category = request.Headers.GetValues("X-Category").FirstOrDefault();
            
            // Use a parameterized approach
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("products.xml");
            
            XPathNavigator navigator = xmlDoc.CreateNavigator();
            XPathExpression expr = navigator.Compile("/products/product[category=$category]");
            
            XsltArgumentList args = new XsltArgumentList();
            args.AddParam("category", "", category);
            
            // ok: xpath-injection-charp-rule
            XPathNodeIterator products = navigator.Select(expr, args);
            
            return View(products);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=0}

        [HttpGet]
        public ActionResult good_case_7()
        {
            // Get user input from query string
            string searchTerm = Request.QueryString["search"];
            
            // Use XmlEncode equivalent for XPath
            string safeSearchTerm = searchTerm.Replace("'", "&apos;");
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("articles.xml");
            
            // ok: xpath-injection-charp-rule
            string xpathQuery = "//articles/article[contains(translate(title,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'" + safeSearchTerm + "')]";
            XmlNodeList articles = xmlDoc.SelectNodes(xpathQuery);
            
            return View(articles);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=0}

        public ActionResult good_case_8()
        {
            // Get user input from multiple sources
            string tag = Request.QueryString["tag"];
            string author = Request.Form["author"];
            
            // Use a different approach - find all and filter in code
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("blog.xml");
            
            // ok: xpath-injection-charp-rule
            XmlNodeList allPosts = xmlDoc.SelectNodes("//blog/post");
            
            // Filter in code instead of XPath
            var filteredPosts = new List<XmlNode>();
            foreach (XmlNode post in allPosts)
            {
                XmlNode authorNode = post.SelectSingleNode("author");
                XmlNodeList tagNodes = post.SelectNodes("tags/tag");
                
                if (authorNode != null && authorNode.InnerText == author &&
                    tagNodes != null && tagNodes.Cast<XmlNode>().Any(t => t.InnerText == tag))
                {
                    filteredPosts.Add(post);
                }
            }
            
            return View(filteredPosts);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=0}

        [HttpPost]
        public ActionResult good_case_9()
        {
            // Get JSON data from request body
            var reader = new StreamReader(Request.InputStream);
            string requestBody = reader.ReadToEnd();
            dynamic data = Newtonsoft.Json.JsonConvert.DeserializeObject(requestBody);
            string productId = data.productId;
            
            // Validate input is numeric
            if (!int.TryParse(productId, out int validProductId))
            {
                return Json(new { error = "Invalid product ID" });
            }
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("inventory.xml");
            
            // ok: xpath-injection-charp-rule
            XmlNode product = xmlDoc.SelectSingleNode($"/inventory/product[@id='{validProductId}']");
            
            return Json(product != null);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=0}

        public ActionResult good_case_10(HttpContext context)
        {
            // Get user input from query parameter
            string attribute = context.Request.Query["attribute"];
            string value = context.Request.Query["value"];
            
            // Validate attribute against whitelist
            string[] allowedAttributes = { "category", "region", "type", "status" };
            if (!allowedAttributes.Contains(attribute))
            {
                return new JsonResult(new { error = "Invalid attribute" });
            }
            
            // Sanitize value
            string safeValue = SecurityElement.Escape(value);
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("data.xml");
            
            // ok: xpath-injection-charp-rule
            string xpathQuery = $"//data/item[@{attribute}='{safeValue}']";
            XmlNodeList items = xmlDoc.SelectNodes(xpathQuery);
            
            return new JsonResult(items);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=0}

        [HttpGet]
        public ActionResult good_case_11()
        {
            // Get user input
            string year = Request.QueryString["year"];
            
            // Strict validation for numeric year
            if (!Regex.IsMatch(year, @"^\d{4}$"))
            {
                return Content("Invalid year format");
            }
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("records.xml");
            
            // ok: xpath-injection-charp-rule
            XmlNodeList records = xmlDoc.SelectNodes($"//records/record[year='{year}']");
            
            return View(records);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=0}

        public ActionResult good_case_12()
        {
            // Get user input from referer header
            string referer = Request.Headers["Referer"];
            string source = HttpUtility.ParseQueryString(new Uri(referer).Query).Get("source");
            
            // Use a custom XPath-safe encoding function
            string SafeForXPath(string input)
            {
                if (string.IsNullOrEmpty(input)) return string.Empty;
                return input.Replace("&", "&amp;")
                           .Replace("<", "&lt;")
                           .Replace(">", "&gt;")
                           .Replace("\"", "&quot;")
                           .Replace("'", "&apos;");
            }
            
            string safeSource = SafeForXPath(source);
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("referrals.xml");
            
            // ok: xpath-injection-charp-rule
            XmlNode referralInfo = xmlDoc.SelectSingleNode("//referrals/referral[@source='" + safeSource + "']");
            
            return View(referralInfo);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=0}

        [HttpPost]
        public ActionResult good_case_13()
        {
            // Get user input from multipart form
            HttpPostedFile file = Request.Files["config"];
            string configName = Path.GetFileNameWithoutExtension(file.FileName);
            
            // Use parameterized XPath
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("configurations.xml");
            
            XPathNavigator navigator = xmlDoc.CreateNavigator();
            XPathExpression expr = navigator.Compile("//configurations/config[@name=$configName]");
            
            XsltArgumentList args = new XsltArgumentList();
            args.AddParam("configName", "", configName);
            
            // ok: xpath-injection-charp-rule
            XPathNodeIterator configNodes = navigator.Select(expr, args);
            
            return View(configNodes);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=0}

        public ActionResult good_case_14()
        {
            // Get user input
            string username = Request.QueryString["username"];
            
            // Use proper XML encoding
            string safeUsername = System.Web.HttpUtility.HtmlEncode(username).Replace("'", "&apos;");
            
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("users.xml");
            
            // ok: xpath-injection-charp-rule
            XmlNodeList users = xmlDoc.SelectNodes("//users/user[username='" + safeUsername + "']");
            
            return View(users);
        }
// {/fact}
// {fact rule=xpath-injection@v1.0 defects=0}

        [HttpGet]
        public ActionResult good_case_15()
        {
            // Get user input from URL fragment
            string fragment = Request.Url.Fragment;
            if (!string.IsNullOrEmpty(fragment))
            {
                fragment = fragment.Substring(1); // Remove the # character
            }
            
            // Use a different approach - load document and navigate in code
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("sections.xml");
            
            // ok: xpath-injection-charp-rule
            XmlNodeList allSections = xmlDoc.SelectNodes("//document/section");
            XmlNode targetSection = null;
            
            foreach (XmlNode section in allSections)
            {
                XmlAttribute idAttr = section.Attributes["id"];
                if (idAttr != null && idAttr.Value == fragment)
                {
                    targetSection = section;
                    break;
                }
            }
            
            return View(targetSection);
        }
// {/fact}
        
        // Helper enum for validation
        private enum UserRole
        {
            Admin,
            User,
            Guest,
            Manager
        }
    }
}