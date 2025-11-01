using System;
using System.Web;
using System.Web.Mvc;
using System.Web.Razor;
using RazorEngine;
using RazorEngine.Templating;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace RazorTemplateInjectionExamples
{
    public class RazorTemplateInjectionController : Controller
    {
// {fact rule=autoescape-disabled@v1.0 defects=1}
        // TRUE POSITIVES (Vulnerable Code)

        public ActionResult bad_case_1()
        {
            // Get user input directly from query string
            string userTemplate = Request.QueryString["template"];
            
            // ruleid: razor-template-injection-csharp-rule
            string result = Razor.Parse(userTemplate, new { Name = "John" });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public ActionResult bad_case_2()
        {
            // Get user input from form
            string userInput = Request.Form["userTemplate"];
            string templateToUse = $"<p>Welcome, @Model.Name!</p>{userInput}";
            
            // ruleid: razor-template-injection-csharp-rule
            var result = Razor.Parse(templateToUse, new { Name = "User" });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public ActionResult bad_case_3()
        {
            // Get user input from cookies
            string userTemplate = Request.Cookies["savedTemplate"]?.Value;
            if (string.IsNullOrEmpty(userTemplate))
            {
                userTemplate = "<p>Default template for @Model.Name</p>";
            }
            
            // ruleid: razor-template-injection-csharp-rule
            string parsedTemplate = Razor.Parse(userTemplate, new { Name = "Guest" });
            
            return Content(parsedTemplate);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public ActionResult bad_case_4()
        {
            // Get user input from headers
            string headerTemplate = Request.Headers["X-Custom-Template"];
            
            // Process the template with some basic transformation
            string processedTemplate = headerTemplate.Replace("[NAME]", "@Model.Name");
            
            // ruleid: razor-template-injection-csharp-rule
            var result = Razor.Parse(processedTemplate, new { Name = "Admin" });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public ActionResult bad_case_5()
        {
            // Get multiple inputs and combine them
            string templateHeader = Request.QueryString["header"];
            string templateBody = Request.QueryString["body"];
            string templateFooter = Request.QueryString["footer"];
            
            string fullTemplate = $"{templateHeader}<div>@Model.Content</div>{templateBody}<footer>{templateFooter}</footer>";
            
            // ruleid: razor-template-injection-csharp-rule
            string result = Razor.Parse(fullTemplate, new { Content = "Main content here" });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        [HttpPost]
        public ActionResult bad_case_6()
        {
            // Get JSON data from request
            var reader = new System.IO.StreamReader(Request.InputStream);
            string requestBody = reader.ReadToEnd();
            dynamic data = Newtonsoft.Json.JsonConvert.DeserializeObject(requestBody);
            
            string template = data.template;
            
            // ruleid: razor-template-injection-csharp-rule
            var result = Razor.Parse(template, new { User = "CurrentUser" });
            
            return Json(new { html = result });
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public ActionResult bad_case_7()
        {
            Dictionary<string, string> templates = new Dictionary<string, string>();
            templates["default"] = "<p>Hello @Model.User</p>";
            
            // Get template selection from user
            string templateKey = Request.QueryString["template"] ?? "default";
            string customTemplate = Request.QueryString["customTemplate"];
            
            // If user provided a custom template, use it instead
            string templateToUse = !string.IsNullOrEmpty(customTemplate) ? customTemplate : templates[templateKey];
            
            // ruleid: razor-template-injection-csharp-rule
            string result = Razor.Parse(templateToUse, new { User = "John" });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        // ASP.NET Core version
        [HttpGet]
        public IActionResult bad_case_8([FromQuery] string templateContent)
        {
            var model = new { Name = "User", Date = DateTime.Now };
            
            // ruleid: razor-template-injection-csharp-rule
            string result = Razor.Parse(templateContent, model);
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        // Using RazorEngine instead of Razor.Parse directly
        public ActionResult bad_case_9()
        {
            string userTemplate = Request.QueryString["template"];
            
            // ruleid: razor-template-injection-csharp-rule
            string result = Engine.Razor.RunCompile(userTemplate, "templateKey", null, new { Name = "John" });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public ActionResult bad_case_10()
        {
            // Get template from URL path
            string path = Request.Path;
            string templateName = path.Substring(path.LastIndexOf('/') + 1);
            string template = $"<h1>Template: {templateName}</h1><div>@Model.Content</div>";
            
            // ruleid: razor-template-injection-csharp-rule
            var result = Razor.Parse(template, new { Content = "Dynamic content" });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        // Using conditional logic but still vulnerable
        public ActionResult bad_case_11()
        {
            string userTemplate = Request.QueryString["template"];
            string mode = Request.QueryString["mode"];
            
            if (mode == "advanced")
            {
                // Even with conditions, still vulnerable
                // ruleid: razor-template-injection-csharp-rule
                return Content(Razor.Parse(userTemplate, new { Data = "Sensitive data" }));
            }
            else
            {
                // Default template is safe, but user template is not
                string defaultTemplate = "<p>Default view for @Model.Data</p>";
                if (!string.IsNullOrEmpty(userTemplate))
                {
                    defaultTemplate = userTemplate;
                }
                
                // ruleid: razor-template-injection-csharp-rule
                return Content(Razor.Parse(defaultTemplate, new { Data = "Basic data" }));
            }
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        // Vulnerable with loop
        public ActionResult bad_case_12()
        {
            string[] templateParts = Request.QueryString["parts"].Split(',');
            string fullTemplate = "";
            
            foreach (var part in templateParts)
            {
                fullTemplate += part + " ";
            }
            
            // ruleid: razor-template-injection-csharp-rule
            string result = Razor.Parse(fullTemplate, new { Items = new[] { "Item1", "Item2", "Item3" } });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        // Vulnerable with switch statement
        public ActionResult bad_case_13()
        {
            string templateType = Request.QueryString["type"];
            string template;
            
            switch (templateType)
            {
                case "html":
                    template = Request.Form["htmlTemplate"];
                    break;
                case "text":
                    template = Request.Form["textTemplate"];
                    break;
                default:
                    template = "<p>@Model.DefaultContent</p>";
                    break;
            }
            
            // ruleid: razor-template-injection-csharp-rule
            string result = Razor.Parse(template, new { DefaultContent = "Default content here" });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        // Vulnerable with try-catch
        public ActionResult bad_case_14()
        {
            string template;
            
            try
            {
                template = Request.QueryString["template"];
                if (string.IsNullOrEmpty(template))
                {
                    throw new Exception("Template not provided");
                }
            }
            catch
            {
                template = "<p>Error occurred. Default template with @Model.ErrorMessage</p>";
            }
            
            // ruleid: razor-template-injection-csharp-rule
            string result = Razor.Parse(template, new { ErrorMessage = "Template processing error" });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        // Vulnerable with LINQ
        public ActionResult bad_case_15()
        {
            var parameters = Request.QueryString.AllKeys
                .Where(k => k.StartsWith("template_"))
                .Select(k => Request.QueryString[k])
                .ToList();
            
            string combinedTemplate = string.Join(" ", parameters);
            
            // ruleid: razor-template-injection-csharp-rule
            string result = Razor.Parse(combinedTemplate, new { Data = "Combined template data" });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        // TRUE NEGATIVES (Safe Code)

        public ActionResult good_case_1()
        {
            // Use predefined templates instead of user input
            string templateName = Request.QueryString["template"];
            string template;
            
            // Use a predefined list of allowed templates
            Dictionary<string, string> allowedTemplates = new Dictionary<string, string>
            {
                ["simple"] = "<p>Hello @Model.Name!</p>",
                ["detailed"] = "<div><h1>Welcome @Model.Name</h1><p>Today is @DateTime.Now</p></div>"
            };
            
            // Only use templates from the allowed list
            if (allowedTemplates.ContainsKey(templateName))
            {
                template = allowedTemplates[templateName];
            }
            else
            {
                template = allowedTemplates["simple"]; // Default template
            }
            
            // ok: razor-template-injection-csharp-rule
            string result = Razor.Parse(template, new { Name = "John" });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public ActionResult good_case_2()
        {
            // Get user input but only use it as data, not as template
            string userName = Request.QueryString["name"];
            
            // Template is hardcoded, user input is only used as data
            string template = "<p>Welcome, @Model.Name!</p><p>Your account was created on @Model.Date</p>";
            
            // ok: razor-template-injection-csharp-rule
            var result = Razor.Parse(template, new { Name = userName, Date = DateTime.Now });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public ActionResult good_case_3()
        {
            // Use an allowlist of template IDs
            string templateId = Request.QueryString["id"];
            string template;
            
            // Map IDs to predefined templates
            switch (templateId)
            {
                case "welcome":
                    template = "<h1>Welcome @Model.User</h1>";
                    break;
                case "profile":
                    template = "<div>Profile for @Model.User</div>";
                    break;
                default:
                    template = "<p>Hello @Model.User</p>";
                    break;
            }
            
            // ok: razor-template-injection-csharp-rule
            string result = Razor.Parse(template, new { User = Request.QueryString["username"] });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public ActionResult good_case_4()
        {
            // User can only customize specific parts of the template
            string userColor = Request.Form["color"];
            string userFontSize = Request.Form["fontSize"];
            
            // Validate user input against allowlist
            string[] allowedColors = { "red", "blue", "green", "black" };
            string[] allowedSizes = { "small", "medium", "large" };
            
            string color = allowedColors.Contains(userColor) ? userColor : "black";
            string fontSize = allowedSizes.Contains(userFontSize) ? userFontSize : "medium";
            
            // Construct template with validated inputs
            string template = $"<div style='color:{color}; font-size:{fontSize};'>Hello @Model.Name!</div>";
            
            // ok: razor-template-injection-csharp-rule
            var result = Razor.Parse(template, new { Name = "User" });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public ActionResult good_case_5()
        {
            // Use a template engine with proper separation of template and data
            string userName = Request.QueryString["name"];
            string userMessage = Request.Form["message"];
            
            // Template is hardcoded
            string template = @"
                <div class='user-message'>
                    <h2>Message from @Model.Name</h2>
                    <p>@Model.Message</p>
                    <span>Posted on @Model.Date</span>
                </div>";
            
            // ok: razor-template-injection-csharp-rule
            string result = Razor.Parse(template, new { 
                Name = HttpUtility.HtmlEncode(userName), 
                Message = HttpUtility.HtmlEncode(userMessage),
                Date = DateTime.Now
            });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        // ASP.NET Core version with safe practices
        [HttpGet]
        public IActionResult good_case_6([FromQuery] string templateType, [FromQuery] string userName)
        {
            // Predefined templates
            Dictionary<string, string> templates = new Dictionary<string, string>
            {
                ["standard"] = "<p>Hello @Model.Name, welcome to our site!</p>",
                ["premium"] = "<div class='premium'><h1>Welcome @Model.Name!</h1><p>Thank you for being a premium member.</p></div>"
            };
            
            // Use default if not in allowlist
            if (!templates.ContainsKey(templateType))
            {
                templateType = "standard";
            }
            
            // ok: razor-template-injection-csharp-rule
            string result = Razor.Parse(templates[templateType], new { Name = userName });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public ActionResult good_case_7()
        {
            // Use a template component system
            string layout = Request.QueryString["layout"];
            
            // Validate layout against allowlist
            string[] allowedLayouts = { "single", "double", "triple" };
            if (!allowedLayouts.Contains(layout))
            {
                layout = "single";
            }
            
            // Construct template based on validated layout
            string template;
            if (layout == "single")
            {
                template = "<div class='single-column'>@Model.Content</div>";
            }
            else if (layout == "double")
            {
                template = "<div class='two-columns'><div>@Model.LeftContent</div><div>@Model.RightContent</div></div>";
            }
            else
            {
                template = "<div class='three-columns'><div>@Model.LeftContent</div><div>@Model.MiddleContent</div><div>@Model.RightContent</div></div>";
            }
            
            // ok: razor-template-injection-csharp-rule
            string result = Razor.Parse(template, new { 
                Content = "Main content",
                LeftContent = "Left sidebar",
                MiddleContent = "Middle content",
                RightContent = "Right sidebar"
            });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public ActionResult good_case_8()
        {
            // Get user input for template customization
            string userTitle = Request.Form["title"];
            string userContent = Request.Form["content"];
            
            // Sanitize user input
            userTitle = HttpUtility.HtmlEncode(userTitle);
            userContent = HttpUtility.HtmlEncode(userContent);
            
            // Use hardcoded template with sanitized user data
            string template = "<article><h1>@Model.Title</h1><div>@Model.Content</div><footer>Posted by @Model.Author</footer></article>";
            
            // ok: razor-template-injection-csharp-rule
            string result = Razor.Parse(template, new { 
                Title = userTitle,
                Content = userContent,
                Author = "Admin"
            });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public ActionResult good_case_9()
        {
            // Use template fragments with validation
            string headerType = Request.QueryString["header"];
            string footerType = Request.QueryString["footer"];
            
            // Validate against allowlist
            Dictionary<string, string> allowedHeaders = new Dictionary<string, string>
            {
                ["simple"] = "<header>@Model.Title</header>",
                ["fancy"] = "<header class='fancy'><h1>@Model.Title</h1></header>"
            };
            
            Dictionary<string, string> allowedFooters = new Dictionary<string, string>
            {
                ["copyright"] = "<footer>&copy; @Model.Year Company</footer>",
                ["contact"] = "<footer>Contact us at @Model.Email</footer>"
            };
            
            // Use default if not in allowlist
            string headerTemplate = allowedHeaders.ContainsKey(headerType) ? allowedHeaders[headerType] : allowedHeaders["simple"];
            string footerTemplate = allowedFooters.ContainsKey(footerType) ? allowedFooters[footerType] : allowedFooters["copyright"];
            
            // Combine validated templates
            string fullTemplate = $"{headerTemplate}<div>@Model.Content</div>{footerTemplate}";
            
            // ok: razor-template-injection-csharp-rule
            string result = Razor.Parse(fullTemplate, new { 
                Title = "Page Title", 
                Content = "Main content here",
                Year = DateTime.Now.Year,
                Email = "contact@example.com"
            });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public ActionResult good_case_10()
        {
            // Use regex to validate template structure
            string userTemplate = Request.Form["template"];
            
            // Define a regex pattern for allowed template structure
            string allowedPattern = @"^<(p|div|span|h[1-6])>[\w\s\.,!?]+</(p|div|span|h[1-6])>$";
            
            if (!Regex.IsMatch(userTemplate, allowedPattern))
            {
                // If not matching allowed pattern, use default template
                userTemplate = "<p>Default template text</p>";
            }
            
            // ok: razor-template-injection-csharp-rule
            string result = Razor.Parse(userTemplate, new { });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        // Using a template repository pattern
        public ActionResult good_case_11()
        {
            string templateId = Request.QueryString["id"];
            
            // Template repository - in real app, this might come from a database
            var templateRepo = new Dictionary<string, string>
            {
                ["user-profile"] = "<div class='profile'><h2>@Model.Name</h2><p>@Model.Bio</p></div>",
                ["product-card"] = "<div class='product'><h3>@Model.ProductName</h3><p>@Model.Price</p></div>",
                ["news-item"] = "<article><h2>@Model.Headline</h2><p>@Model.Story</p></article>"
            };
            
            // Only use templates from the repository
            if (!templateRepo.ContainsKey(templateId))
            {
                templateId = "user-profile"; // Default template
            }
            
            // ok: razor-template-injection-csharp-rule
            string result = Razor.Parse(templateRepo[templateId], new { 
                Name = "John Doe", 
                Bio = "Software developer",
                ProductName = "Sample Product",
                Price = "$19.99",
                Headline = "Breaking News",
                Story = "This is a news story."
            });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        // Using template inheritance safely
        public ActionResult good_case_12()
        {
            string pageType = Request.QueryString["page"];
            
            // Base template is fixed
            string baseTemplate = "@RenderSection(\"header\", required: false)<div class='content'>@RenderBody()</div>@RenderSection(\"footer\", required: false)";
            
            // Page templates are predefined
            Dictionary<string, string> pageTemplates = new Dictionary<string, string>
            {
                ["home"] = "@section header { <h1>Home Page</h1> } Welcome to our site! @section footer { <p>Home page footer</p> }",
                ["about"] = "@section header { <h1>About Us</h1> } Learn about our company. @section footer { <p>About page footer</p> }",
                ["contact"] = "@section header { <h1>Contact</h1> } Get in touch with us. @section footer { <p>Contact page footer</p> }"
            };
            
            // Use default if not in allowlist
            if (!pageTemplates.ContainsKey(pageType))
            {
                pageType = "home";
            }
            
            // Combine templates safely
            string combinedTemplate = baseTemplate.Replace("@RenderBody()", pageTemplates[pageType]);
            
            // ok: razor-template-injection-csharp-rule
            string result = Razor.Parse(combinedTemplate, new { });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        // Using template with safe dynamic content
        public ActionResult good_case_13()
        {
            // Get user preferences
            string theme = Request.Cookies["theme"]?.Value ?? "light";
            string fontSize = Request.Cookies["fontSize"]?.Value ?? "medium";
            
            // Validate against allowlist
            string[] allowedThemes = { "light", "dark", "blue" };
            string[] allowedFontSizes = { "small", "medium", "large" };
            
            theme = allowedThemes.Contains(theme) ? theme : "light";
            fontSize = allowedFontSizes.Contains(fontSize) ? fontSize : "medium";
            
            // Fixed template with validated dynamic content
            string template = $"<div class='theme-{theme} font-{fontSize}'><h1>@Model.Title</h1><p>@Model.Content</p></div>";
            
            // ok: razor-template-injection-csharp-rule
            string result = Razor.Parse(template, new { 
                Title = "Welcome to our site", 
                Content = "This content is displayed with your preferred settings." 
            });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        // Using component-based templates
        public ActionResult good_case_14()
        {
            // Get component selection from user
            string[] requestedComponents = Request.QueryString["components"]?.Split(',') ?? new string[0];
            
            // Define allowed components
            Dictionary<string, string> allowedComponents = new Dictionary<string, string>
            {
                ["header"] = "<header><h1>@Model.Title</h1></header>",
                ["sidebar"] = "<aside><nav>@Model.Navigation</nav></aside>",
                ["content"] = "<main>@Model.MainContent</main>",
                ["footer"] = "<footer>@Model.FooterText</footer>"
            };
            
            // Build template using only allowed components
            string template = "<div class='container'>";
            foreach (var component in requestedComponents)
            {
                if (allowedComponents.ContainsKey(component))
                {
                    template += allowedComponents[component];
                }
            }
            template += "</div>";
            
            // If no valid components were selected, use a default template
            if (template == "<div class='container'></div>")
            {
                template = "<div class='container'>" + allowedComponents["header"] + allowedComponents["content"] + "</div>";
            }
            
            // ok: razor-template-injection-csharp-rule
            string result = Razor.Parse(template, new { 
                Title = "Page Title",
                Navigation = "<ul><li>Home</li><li>About</li></ul>",
                MainContent = "<p>Main page content</p>",
                FooterText = "Copyright 2023"
            });
            
            return Content(result);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        // Using template with safe conditional rendering
        public ActionResult good_case_15()
        {
            // Get user preferences
            bool showHeader = Convert.ToBoolean(Request.QueryString["showHeader"] ?? "true");
            bool showFooter = Convert.ToBoolean(Request.QueryString["showFooter"] ?? "true");
            bool showSidebar = Convert.ToBoolean(Request.QueryString["showSidebar"] ?? "false");
            
            // Build template with conditional sections
            string template = "<div class='page'>";
            
            if (showHeader)
            {
                template += "<header>@Model.HeaderContent</header>";
            }
            
            template += "<div class='main-content'>";
            
            if (showSidebar)
            {
                template += "<aside>@Model.SidebarContent</aside>";
            }
            
            template += "<main>@Model.MainContent</main></div>";
            
            if (showFooter)
            {
                template += "<footer>@Model.FooterContent</footer>";
            }
            
            template += "</div>";
            
            // ok: razor-template-injection-csharp-rule
            string result = Razor.Parse(template, new { 
                HeaderContent = "<h1>Site Title</h1>",
                SidebarContent = "<nav><ul><li>Link 1</li><li>Link 2</li></ul></nav>",
                MainContent = "<article><h2>Article Title</h2><p>Article content</p></article>",
                FooterContent = "<p>&copy; 2023 Company</p>"
            });
            
            return Content(result);
        }
// {/fact}
    }
}