using System;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.Mvc;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.IO;
using System.Text;
using Microsoft.Security.Application; // For AntiXSS

namespace XssTestCases
{
    public class XssExamples
    {
// {fact rule=autoescape-disabled@v1.0 defects=1}
        // True Positives (Vulnerable Code)

        public void bad_case_1(HttpContext context)
        {
            string userInput = context.Request.QueryString["input"];
            
            // ruleid: csharp-cross-site-scripting-ide
            context.Response.Write("<div>" + userInput + "</div>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public void bad_case_2(HttpContext context)
        {
            string userComment = context.Request.Form["comment"];
            StringBuilder sb = new StringBuilder();
            sb.Append("<p>Your comment: ");
            
            // ruleid: csharp-cross-site-scripting-ide
            sb.Append(userComment);
            sb.Append("</p>");
            context.Response.Write(sb.ToString());
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public void bad_case_3(HttpContext context)
        {
            string username = context.Request.QueryString["username"];
            string html = "<script>var currentUser = '" + 
                // ruleid: csharp-cross-site-scripting-ide
                username + 
                "';</script>";
            context.Response.Write(html);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public void bad_case_4(HttpContext context)
        {
            string searchTerm = context.Request.QueryString["q"];
            
            // ruleid: csharp-cross-site-scripting-ide
            context.Response.Write($"<h2>Search results for: {searchTerm}</h2>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public void bad_case_5(HttpContext context)
        {
            string userId = context.Request.Headers["X-User-Id"];
            
            // ruleid: csharp-cross-site-scripting-ide
            context.Response.Write("<div data-user-id=\"" + userId + "\">User Profile</div>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public void bad_case_6(HttpContext context)
        {
            string color = context.Request.QueryString["color"];
            
            // ruleid: csharp-cross-site-scripting-ide
            context.Response.Write("<div style='background-color:" + color + "'>Colored Box</div>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public void bad_case_7(HttpContext context)
        {
            string redirectUrl = context.Request.QueryString["url"];
            
            // ruleid: csharp-cross-site-scripting-ide
            context.Response.Write("<a href='" + redirectUrl + "'>Click here</a>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public void bad_case_8(HttpContext context)
        {
            string userInput = context.Request.Form["input"];
            if (userInput.Contains("script"))
            {
                userInput = userInput.Replace("script", "");
            }
            
            // ruleid: csharp-cross-site-scripting-ide
            context.Response.Write("<div>" + userInput + "</div>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public void bad_case_9(HttpContext context)
        {
            string jsonData = context.Request.Form["data"];
            
            // ruleid: csharp-cross-site-scripting-ide
            context.Response.Write("<script>var data = " + jsonData + ";</script>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public void bad_case_10(HttpContext context)
        {
            string userAgent = context.Request.Headers["User-Agent"];
            
            // ruleid: csharp-cross-site-scripting-ide
            context.Response.Write("<div>Your browser: " + userAgent + "</div>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public void bad_case_11(HttpContext context)
        {
            string cookieValue = context.Request.Cookies["preference"].Value;
            
            // ruleid: csharp-cross-site-scripting-ide
            context.Response.Write("<div>Your preference: " + cookieValue + "</div>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public void bad_case_12(HttpContext context)
        {
            string title = context.Request.QueryString["title"];
            string content = context.Request.Form["content"];
            
            // ruleid: csharp-cross-site-scripting-ide
            context.Response.Write($"<article><h1>{title}</h1><div>{content}</div></article>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public void bad_case_13(HttpContext context)
        {
            string errorMessage = context.Request.QueryString["error"];
            
            // ruleid: csharp-cross-site-scripting-ide
            context.Response.Write("<div class='error'>" + errorMessage + "</div>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public void bad_case_14(HttpContext context)
        {
            string username = context.Request.QueryString["user"];
            string message = "Welcome, " + username;
            
            // ruleid: csharp-cross-site-scripting-ide
            context.Response.Write("<h1>" + message + "</h1>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

        public void bad_case_15(HttpContext context)
        {
            string customJs = context.Request.Form["customJs"];
            
            // ruleid: csharp-cross-site-scripting-ide
            context.Response.Write("<script>" + customJs + "</script>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        // True Negatives (Safe Code)

        public void good_case_1(HttpContext context)
        {
            string userInput = context.Request.QueryString["input"];
            
            // ok: csharp-cross-site-scripting-ide
            context.Response.Write("<div>" + HttpUtility.HtmlEncode(userInput) + "</div>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public void good_case_2(HttpContext context)
        {
            string userComment = context.Request.Form["comment"];
            StringBuilder sb = new StringBuilder();
            sb.Append("<p>Your comment: ");
            
            // ok: csharp-cross-site-scripting-ide
            sb.Append(HttpUtility.HtmlEncode(userComment));
            sb.Append("</p>");
            context.Response.Write(sb.ToString());
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public void good_case_3(HttpContext context)
        {
            string username = context.Request.QueryString["username"];
            
            // ok: csharp-cross-site-scripting-ide
            string html = "<script>var currentUser = '" + 
                HttpUtility.JavaScriptStringEncode(username) + 
                "';</script>";
            context.Response.Write(html);
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public void good_case_4(HttpContext context)
        {
            string searchTerm = context.Request.QueryString["q"];
            
            // ok: csharp-cross-site-scripting-ide
            context.Response.Write($"<h2>Search results for: {HttpUtility.HtmlEncode(searchTerm)}</h2>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public void good_case_5(HttpContext context)
        {
            string userId = context.Request.Headers["X-User-Id"];
            
            // ok: csharp-cross-site-scripting-ide
            context.Response.Write("<div data-user-id=\"" + HttpUtility.HtmlAttributeEncode(userId) + "\">User Profile</div>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public void good_case_6(HttpContext context)
        {
            string color = context.Request.QueryString["color"];
            // Validate color format (simple validation example)
            if (System.Text.RegularExpressions.Regex.IsMatch(color, "^#[0-9A-Fa-f]{6}$"))
            {
                // ok: csharp-cross-site-scripting-ide
                context.Response.Write("<div style='background-color:" + color + "'>Colored Box</div>");
            }
            else
            {
                context.Response.Write("<div>Invalid color format</div>");
            }
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public void good_case_7(HttpContext context)
        {
            string redirectUrl = context.Request.QueryString["url"];
            Uri uri;
            if (Uri.TryCreate(redirectUrl, UriKind.Absolute, out uri) && 
                (uri.Scheme == "http" || uri.Scheme == "https"))
            {
                // ok: csharp-cross-site-scripting-ide
                context.Response.Write("<a href='" + HttpUtility.HtmlAttributeEncode(redirectUrl) + "'>Click here</a>");
            }
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public void good_case_8(HttpContext context)
        {
            string userInput = context.Request.Form["input"];
            
            // ok: csharp-cross-site-scripting-ide
            string safeOutput = AntiXss.HtmlEncode(userInput);
            context.Response.Write("<div>" + safeOutput + "</div>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public void good_case_9(HttpContext context)
        {
            string jsonData = context.Request.Form["data"];
            
            // ok: csharp-cross-site-scripting-ide
            context.Response.Write("<script>var data = " + 
                HttpUtility.JavaScriptStringEncode(jsonData) + 
                ";</script>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public void good_case_10(HttpContext context)
        {
            string userAgent = context.Request.Headers["User-Agent"];
            
            // ok: csharp-cross-site-scripting-ide
            context.Response.Write("<div>Your browser: " + HttpUtility.HtmlEncode(userAgent) + "</div>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public void good_case_11(HttpContext context)
        {
            if (context.Request.Cookies["preference"] != null)
            {
                string cookieValue = context.Request.Cookies["preference"].Value;
                
                // ok: csharp-cross-site-scripting-ide
                context.Response.Write("<div>Your preference: " + HttpUtility.HtmlEncode(cookieValue) + "</div>");
            }
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public void good_case_12(HttpContext context)
        {
            string title = context.Request.QueryString["title"];
            string content = context.Request.Form["content"];
            
            // ok: csharp-cross-site-scripting-ide
            context.Response.Write($"<article><h1>{HttpUtility.HtmlEncode(title)}</h1><div>{HttpUtility.HtmlEncode(content)}</div></article>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public void good_case_13(HttpContext context)
        {
            string errorMessage = context.Request.QueryString["error"];
            
            // Using a whitelist of allowed error messages
            string[] allowedErrors = { "not_found", "access_denied", "server_error" };
            string displayError = "Unknown error";
            
            foreach (string allowed in allowedErrors)
            {
                if (errorMessage == allowed)
                {
                    displayError = errorMessage;
                    break;
                }
            }
            
            // ok: csharp-cross-site-scripting-ide
            context.Response.Write("<div class='error'>" + displayError + "</div>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public void good_case_14(HttpContext context)
        {
            string username = context.Request.QueryString["user"];
            
            // ok: csharp-cross-site-scripting-ide
            var encodedUsername = HttpUtility.HtmlEncode(username);
            string message = "Welcome, " + encodedUsername;
            context.Response.Write("<h1>" + message + "</h1>");
        }
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

        public void good_case_15(HttpContext context)
        {
            // Instead of accepting arbitrary JavaScript, use a predefined set
            string jsOption = context.Request.Form["jsOption"];
            string customJs = "";
            
            if (jsOption == "analytics")
            {
                customJs = "initAnalytics();";
            }
            else if (jsOption == "charts")
            {
                customJs = "loadCharts();";
            }
            
            // ok: csharp-cross-site-scripting-ide
            context.Response.Write("<script>" + customJs + "</script>");
        }
// {/fact}
    }
}