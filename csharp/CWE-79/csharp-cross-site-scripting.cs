using System;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.Mvc;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.Security.Application; // For AntiXSS
// {fact rule=autoescape-disabled@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

public void bad_case_1(HttpContext context)
{
    string userInput = context.Request.QueryString["name"];
    
    // ruleid: csharp-cross-site-scripting
    context.Response.Write("<div>" + userInput + "</div>");
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

public void bad_case_2(HttpContext context)
{
    string userComment = context.Request.Form["comment"];
    
    // ruleid: csharp-cross-site-scripting
    context.Response.Write($"<p>Your comment: {userComment}</p>");
}
// {/fact}

public class bad_case_3 : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        string searchTerm = Request.QueryString["q"];
        
        // ruleid: csharp-cross-site-scripting
        LiteralControl literal = new LiteralControl("<div>Search results for: " + searchTerm + "</div>");
        this.Controls.Add(literal);
    }
}

public class bad_case_4 : System.Web.UI.Page
{
    protected void Button_Click(object sender, EventArgs e)
    {
        string username = Request.Form["username"];
        
        // ruleid: csharp-cross-site-scripting
        Response.Write("<script>var currentUser = '" + username + "';</script>");
    }
}

public class bad_case_5 : Controller
{
    public ActionResult Index()
    {
        string message = Request.QueryString["message"];
        
        // ruleid: csharp-cross-site-scripting
        ViewBag.Message = message;
        return View();
    }
}

public class bad_case_6 : Controller
{
    public ActionResult Search()
    {
        string query = Request.QueryString["q"];
        
        // ruleid: csharp-cross-site-scripting
        return Content("<h2>Search results for: " + query + "</h2>", "text/html");
    }
}

public class bad_case_7 : Controller
{
    public string GetUserProfile()
    {
        string userId = Request.QueryString["id"];
        
        // ruleid: csharp-cross-site-scripting
        return "<div class='profile' data-id='" + userId + "'>User profile</div>";
    }
}

public class bad_case_8 : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        string userAgent = Request.Headers["User-Agent"];
        
        // ruleid: csharp-cross-site-scripting
        ClientScript.RegisterStartupScript(this.GetType(), "UserAgentScript", 
            "console.log('User agent: " + userAgent + "');", true);
    }
}

public class bad_case_9 : Controller
{
    public ActionResult DisplayError()
    {
        string errorMsg = Request.QueryString["error"];
        
        // ruleid: csharp-cross-site-scripting
        TempData["ErrorMessage"] = "<strong>" + errorMsg + "</strong>";
        return RedirectToAction("Error");
    }
}

public class bad_case_10 : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        if (Request.Cookies["preferences"] != null)
        {
            string theme = Request.Cookies["preferences"].Value;
            
            // ruleid: csharp-cross-site-scripting
            Response.Write("<div style='" + theme + "'>Content with user preferences</div>");
        }
    }
}

public class bad_case_11 : Controller
{
    [HttpPost]
    public ActionResult UpdateProfile()
    {
        string bio = Request.Form["bio"];
        
        // ruleid: csharp-cross-site-scripting
        ViewBag.SuccessMessage = "<div class='alert'>Profile updated! Bio: " + bio + "</div>";
        return View();
    }
}

public class bad_case_12 : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        string referer = Request.Headers["Referer"];
        
        // ruleid: csharp-cross-site-scripting
        Response.Write("<a href='" + referer + "'>Go back</a>");
    }
}

public class bad_case_13 : Controller
{
    public ActionResult RenderWidget()
    {
        string widgetId = Request.QueryString["widget"];
        string widgetTitle = Request.QueryString["title"];
        
        // ruleid: csharp-cross-site-scripting
        return Content($"<div id='{widgetId}'><h3>{widgetTitle}</h3><div class='content'></div></div>", "text/html");
    }
}

public class bad_case_14 : System.Web.UI.Page
{
    protected void Button_Click(object sender, EventArgs e)
    {
        string searchQuery = Request.Form["search"];
        
        // ruleid: csharp-cross-site-scripting
        Response.Write(@"
            <script>
                document.getElementById('lastSearch').innerHTML = 'Last search: " + searchQuery + "';
            </script>
        ");
    }
}

public class bad_case_15 : Controller
{
    [HttpPost]
    public JsonResult SaveComment()
    {
        string comment = Request.Form["comment"];
        string username = Request.Form["username"];
        
        // Save comment to database
        
        // ruleid: csharp-cross-site-scripting
        return Json(new { 
            success = true, 
            html = "<div class='comment'><strong>" + username + "</strong>: " + comment + "</div>" 
        });
    }
}
// {fact rule=autoescape-disabled@v1.0 defects=0}

// True Negative Examples (Secure Code)

public void good_case_1(HttpContext context)
{
    string userInput = context.Request.QueryString["name"];
    
    // ok: csharp-cross-site-scripting
    context.Response.Write("<div>" + HttpUtility.HtmlEncode(userInput) + "</div>");
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

public void good_case_2(HttpContext context)
{
    string userComment = context.Request.Form["comment"];
    
    // ok: csharp-cross-site-scripting
    context.Response.Write($"<p>Your comment: {HttpUtility.HtmlEncode(userComment)}</p>");
}
// {/fact}

public class good_case_3 : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        string searchTerm = Request.QueryString["q"];
        
        // ok: csharp-cross-site-scripting
        Label searchLabel = new Label();
        searchLabel.Text = "Search results for: " + HttpUtility.HtmlEncode(searchTerm);
        this.Controls.Add(searchLabel);
    }
}

public class good_case_4 : System.Web.UI.Page
{
    protected void Button_Click(object sender, EventArgs e)
    {
        string username = Request.Form["username"];
        
        // ok: csharp-cross-site-scripting
        string safeUsername = HttpUtility.JavaScriptStringEncode(username);
        Response.Write("<script>var currentUser = '" + safeUsername + "';</script>");
    }
}

public class good_case_5 : Controller
{
    public ActionResult Index()
    {
        string message = Request.QueryString["message"];
        
        // ok: csharp-cross-site-scripting
        ViewBag.Message = HttpUtility.HtmlEncode(message);
        return View();
    }
}

public class good_case_6 : Controller
{
    public ActionResult Search()
    {
        string query = Request.QueryString["q"];
        
        // ok: csharp-cross-site-scripting
        return Content("<h2>Search results for: " + HttpUtility.HtmlEncode(query) + "</h2>", "text/html");
    }
}

public class good_case_7 : Controller
{
    public string GetUserProfile()
    {
        string userId = Request.QueryString["id"];
        
        // ok: csharp-cross-site-scripting
        return "<div class='profile' data-id='" + HttpUtility.HtmlAttributeEncode(userId) + "'>User profile</div>";
    }
}

public class good_case_8 : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        string userAgent = Request.Headers["User-Agent"];
        
        // ok: csharp-cross-site-scripting
        string safeUserAgent = HttpUtility.JavaScriptStringEncode(userAgent);
        ClientScript.RegisterStartupScript(this.GetType(), "UserAgentScript", 
            "console.log('User agent: " + safeUserAgent + "');", true);
    }
}

public class good_case_9 : Controller
{
    public ActionResult DisplayError()
    {
        string errorMsg = Request.QueryString["error"];
        
        // ok: csharp-cross-site-scripting
        TempData["ErrorMessage"] = AntiXss.HtmlEncode(errorMsg);
        return RedirectToAction("Error");
    }
}

public class good_case_10 : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        if (Request.Cookies["preferences"] != null)
        {
            string theme = Request.Cookies["preferences"].Value;
            
            // Validate theme against allowed values
            string[] allowedThemes = { "dark", "light", "blue", "green" };
            
            // ok: csharp-cross-site-scripting
            if (Array.IndexOf(allowedThemes, theme) >= 0)
            {
                Response.Write("<div class='theme-" + theme + "'>Content with user preferences</div>");
            }
            else
            {
                Response.Write("<div class='theme-default'>Content with default theme</div>");
            }
        }
    }
}

public class good_case_11 : Controller
{
    [HttpPost]
    public ActionResult UpdateProfile()
    {
        string bio = Request.Form["bio"];
        
        // ok: csharp-cross-site-scripting
        ViewBag.SuccessMessage = string.Format("<div class='alert'>Profile updated! Bio: {0}</div>", 
            HttpUtility.HtmlEncode(bio));
        return View();
    }
}

public class good_case_12 : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        string referer = Request.Headers["Referer"];
        
        // ok: csharp-cross-site-scripting
        Uri refererUri;
        if (Uri.TryCreate(referer, UriKind.Absolute, out refererUri) && 
            (refererUri.Host == "trusted-domain.com" || refererUri.Host == "another-trusted.com"))
        {
            Response.Write("<a href='" + HttpUtility.HtmlAttributeEncode(referer) + "'>Go back</a>");
        }
        else
        {
            Response.Write("<a href='/'>Go home</a>");
        }
    }
}

public class good_case_13 : Controller
{
    public ActionResult RenderWidget()
    {
        string widgetId = Request.QueryString["widget"];
        string widgetTitle = Request.QueryString["title"];
        
        // ok: csharp-cross-site-scripting
        return Content($"<div id='{HttpUtility.HtmlAttributeEncode(widgetId)}'><h3>{HttpUtility.HtmlEncode(widgetTitle)}</h3><div class='content'></div></div>", "text/html");
    }
}

public class good_case_14 : System.Web.UI.Page
{
    protected void Button_Click(object sender, EventArgs e)
    {
        string searchQuery = Request.Form["search"];
        
        // ok: csharp-cross-site-scripting
        string safeSearchQuery = HttpUtility.JavaScriptStringEncode(searchQuery);
        Response.Write(@"
            <script>
                document.getElementById('lastSearch').textContent = 'Last search: " + safeSearchQuery + "';
            </script>
        ");
    }
}

public class good_case_15 : Controller
{
    [HttpPost]
    public JsonResult SaveComment()
    {
        string comment = Request.Form["comment"];
        string username = Request.Form["username"];
        
        // Save comment to database
        
        // ok: csharp-cross-site-scripting
        string safeHtml = "<div class='comment'><strong>" + 
            HttpUtility.HtmlEncode(username) + 
            "</strong>: " + 
            HttpUtility.HtmlEncode(comment) + 
            "</div>";
            
        return Json(new { 
            success = true, 
            html = safeHtml 
        });
    }
}