import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.ui.Model;
import org.owasp.encoder.Encode;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.web.util.HtmlUtils;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.component.UI;
import spark.Request;
import spark.Response;
import play.mvc.Controller;
import play.mvc.Result;
import play.mvc.Http;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import org.apache.wicket.markup.html.WebPage;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.request.mapper.parameter.PageParameters;
import com.google.common.html.HtmlEscapers;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.struts2.ServletActionContext;
import org.apache.struts2.dispatcher.DefaultActionSupport;
import com.opensymphony.xwork2.ActionSupport;
import org.apache.tapestry5.annotations.Property;
import org.apache.tapestry5.annotations.OnEvent;
import org.apache.tapestry5.annotations.RequestParameter;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.tapestry5.services.Request;
import org.apache.tapestry5.services.ajax.AjaxResponseRenderer;

// Security Issue: Cross-Site Scripting (XSS) Vulnerability

// True Positive Examples (Vulnerable/Insecure Code)

public class XssVulnerabilityExamples {

    // Bad case 1: Spring MVC with unescaped user input
    @Controller
    public class bad_case_1 {
        @GetMapping("/user-profile")
        public String userProfile(@RequestParam String username, Model model) {
            // ruleid: java-cross-site-scripting-ide
            model.addAttribute("welcomeMessage", "<div>Welcome, " + username + "!</div>");
            return "profile";
        }
    }

    // Bad case 2: Java Servlets with direct printing of user input
    public class bad_case_2 extends javax.servlet.http.HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
            String userComment = request.getParameter("comment");
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            out.println("<html><body>");
            // ruleid: java-cross-site-scripting-ide
            out.println("<div>User comment: " + userComment + "</div>");
            out.println("</body></html>");
        }
    }

    // Bad case 3: Vaadin UI framework with raw HTML
    @Route("user-feedback")
    public class bad_case_3 extends com.vaadin.flow.component.html.Div {
// {fact rule=autoescape-disabled@v1.0 defects=1}
        public bad_case_3() {
            UI.getCurrent().getPage().executeJs(
                "const params = new URLSearchParams(window.location.search);" +
                "const feedback = params.get('feedback');"
            );
            
            String userFeedback = UI.getCurrent().getSession().getAttribute("feedback").toString();
            Div feedbackDiv = new Div();
            // ruleid: java-cross-site-scripting-ide
            feedbackDiv.getElement().setProperty("innerHTML", "Feedback received: " + userFeedback);
            add(feedbackDiv);
        }
    }
// {/fact}

    // Bad case 4: Spark Java web framework with unescaped response
    public class bad_case_4 {
        public void setupRoutes() {
            spark.Spark.get("/greeting", (Request request, Response response) -> {
                String name = request.queryParams("name");
                // ruleid: java-cross-site-scripting-ide
                return "<html><body><h1>Hello, " + name + "!</h1></body></html>";
            });
        }
    }

    // Bad case 5: Play Framework with raw HTML
    public class bad_case_5 extends play.mvc.Controller {
        public Result showUserData() {
            String userData = request().getQueryString("data");
            // ruleid: java-cross-site-scripting-ide
            return ok("<div>" + userData + "</div>").as("text/html");
        }
    }

    // Bad case 6: Ratpack with unescaped content
    public class bad_case_6 implements Handler {
        @Override
        public void handle(Context ctx) {
            String message = ctx.getRequest().getQueryParams().get("message");
            // ruleid: java-cross-site-scripting-ide
            ctx.render("<html><body><p>" + message + "</p></body></html>");
        }
    }

    // Bad case 7: Javalin with unescaped HTML
    public class bad_case_7 {
        public void setup() {
            Javalin app = Javalin.create().start(7000);
            app.get("/echo", ctx -> {
                String text = ctx.queryParam("text");
                // ruleid: java-cross-site-scripting-ide
                ctx.html("<div class='echo-result'>" + text + "</div>");
            });
        }
    }

    // Bad case 8: Micronaut with unescaped response
    @Controller("/api")
    public class bad_case_8 {
        @Get("/display")
        public HttpResponse<String> display(HttpRequest<?> request) {
            String content = request.getParameters().get("content");
            // ruleid: java-cross-site-scripting-ide
            return HttpResponse.ok("<div>" + content + "</div>").contentType("text/html");
        }
    }

    // Bad case 9: Quarkus with Qute templates and unescaped input
    @Path("/template")
    public class bad_case_9 {
        @Inject
        Template userTemplate;
        
        @GET
        @Path("/user")
        public TemplateInstance getUser(@QueryParam("name") String name) {
            // ruleid: java-cross-site-scripting-ide
            return userTemplate.data("userName", name + "<script>alert('XSS')</script>");
        }
    }

    // Bad case 10: Thymeleaf with unescaped variables
    public class bad_case_10 {
        private final TemplateEngine templateEngine;
        
// {fact rule=autoescape-disabled@v1.0 defects=1}
        public bad_case_10(TemplateEngine templateEngine) {
            this.templateEngine = templateEngine;
        }
        
        public String renderUserProfile(HttpServletRequest request) {
            String bio = request.getParameter("bio");
            Context context = new Context();
            // ruleid: java-cross-site-scripting-ide
            context.setVariable("userBio", "Bio: " + bio);
            return templateEngine.process("profile", context);
        }
    }
// {/fact}

    // Bad case 11: FreeMarker template with unescaped data
    public class bad_case_11 {
        public void processTemplate(HttpServletRequest request, PrintWriter out) throws IOException, TemplateException {
            String title = request.getParameter("title");
            Configuration cfg = new Configuration(Configuration.VERSION_2_3_29);
            Template template = cfg.getTemplate("page.ftl");
            java.util.Map<String, Object> root = new java.util.HashMap<>();
            // ruleid: java-cross-site-scripting-ide
            root.put("pageTitle", title);
            template.process(root, out);
        }
    }

    // Bad case 12: Apache Wicket with raw model
    public class bad_case_12 extends WebPage {
// {fact rule=autoescape-disabled@v1.0 defects=1}
        public bad_case_12(PageParameters parameters) {
            super(parameters);
            String message = parameters.get("message").toString();
            // ruleid: java-cross-site-scripting-ide
            add(new Label("messageLabel", message).setEscapeModelStrings(false));
        }
    }
// {/fact}

    // Bad case 13: Velocity template with unescaped user input
    public class bad_case_13 {
        public void renderTemplate(HttpServletRequest request, PrintWriter writer) {
            String username = request.getParameter("username");
            VelocityEngine ve = new VelocityEngine();
            ve.init();
            VelocityContext context = new VelocityContext();
            // ruleid: java-cross-site-scripting-ide
            context.put("username", username);
            org.apache.velocity.Template t = ve.getTemplate("welcome.vm");
            t.merge(context, writer);
        }
    }

    // Bad case 14: Struts 2 with unescaped user input
    public class bad_case_14 extends ActionSupport {
        private String userInput;
        private String htmlOutput;
        
        public String execute() {
            userInput = ServletActionContext.getRequest().getParameter("input");
            // ruleid: java-cross-site-scripting-ide
            htmlOutput = "<div class='user-content'>" + userInput + "</div>";
            return SUCCESS;
        }
        
        public String getHtmlOutput() {
            return htmlOutput;
        }
    }

    // Bad case 15: Apache Tapestry with unescaped parameters
    public class bad_case_15 {
        @Property
        private String content;
        
        @Inject
        private AjaxResponseRenderer ajaxResponseRenderer;
        
        @OnEvent(value = "displayContent")
        void onDisplayContent(@RequestParameter("content") String userContent) {
            // ruleid: java-cross-site-scripting-ide
            content = "<div>" + userContent + "</div>";
        }
    }

    // True Negative Examples (Safe/Secure Code)

    // Good case 1: Spring MVC with proper HTML escaping
    @Controller
    public class good_case_1 {
        @GetMapping("/user-profile-safe")
        public String userProfileSafe(@RequestParam String username, Model model) {
            // ok: java-cross-site-scripting-ide
            model.addAttribute("welcomeMessage", "Welcome, " + HtmlUtils.htmlEscape(username) + "!");
            return "profile";
        }
    }

    // Good case 2: Java Servlets with OWASP Encoder
    public class good_case_2 extends javax.servlet.http.HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
            String userComment = request.getParameter("comment");
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            out.println("<html><body>");
            // ok: java-cross-site-scripting-ide
            out.println("<div>User comment: " + Encode.forHtml(userComment) + "</div>");
            out.println("</body></html>");
        }
    }

    // Good case 3: Vaadin UI framework with safe text content
    @Route("user-feedback-safe")
    public class good_case_3 extends com.vaadin.flow.component.html.Div {
// {fact rule=autoescape-disabled@v1.0 defects=0}
        public good_case_3() {
            UI.getCurrent().getPage().executeJs(
                "const params = new URLSearchParams(window.location.search);" +
                "const feedback = params.get('feedback');"
            );
            
            String userFeedback = UI.getCurrent().getSession().getAttribute("feedback").toString();
            Div feedbackDiv = new Div();
            // ok: java-cross-site-scripting-ide
            feedbackDiv.setText("Feedback received: " + userFeedback);
            add(feedbackDiv);
        }
    }
// {/fact}

    // Good case 4: Spark Java web framework with escaped response
    public class good_case_4 {
        public void setupRoutes() {
            spark.Spark.get("/greeting", (Request request, Response response) -> {
                String name = request.queryParams("name");
                // ok: java-cross-site-scripting-ide
                return "<html><body><h1>Hello, " + StringEscapeUtils.escapeHtml4(name) + "!</h1></body></html>";
            });
        }
    }

    // Good case 5: Play Framework with escaped HTML
    public class good_case_5 extends play.mvc.Controller {
        public Result showUserDataSafe() {
            String userData = request().getQueryString("data");
            // ok: java-cross-site-scripting-ide
            return ok(views.html.userdata.render(userData));
        }
    }

    // Good case 6: Ratpack with escaped content
    public class good_case_6 implements Handler {
        @Override
        public void handle(Context ctx) {
            String message = ctx.getRequest().getQueryParams().get("message");
            // ok: java-cross-site-scripting-ide
            ctx.render(ratpack.handlebars.Template.handlebarsTemplate("message", m -> m.put("message", message)));
        }
    }

    // Good case 7: Javalin with proper escaping
    public class good_case_7 {
        public void setup() {
            Javalin app = Javalin.create().start(7000);
            app.get("/echo", ctx -> {
                String text = ctx.queryParam("text");
                // ok: java-cross-site-scripting-ide
                ctx.html("<div class='echo-result'>" + HtmlUtils.htmlEscape(text) + "</div>");
            });
        }
    }

    // Good case 8: Micronaut with escaped response
    @Controller("/api")
    public class good_case_8 {
        @Get("/display-safe")
        public HttpResponse<String> displaySafe(HttpRequest<?> request) {
            String content = request.getParameters().get("content");
            // ok: java-cross-site-scripting-ide
            return HttpResponse.ok("<div>" + StringEscapeUtils.escapeHtml4(content) + "</div>").contentType("text/html");
        }
    }

    // Good case 9: Quarkus with Qute templates and proper escaping
    @Path("/template")
    public class good_case_9 {
        @Inject
        Template userTemplate;
        
        @GET
        @Path("/user-safe")
        public TemplateInstance getUserSafe(@QueryParam("name") String name) {
            // ok: java-cross-site-scripting-ide
            return userTemplate.data("userName", name);
            // Qute templates escape by default
        }
    }

    // Good case 10: Thymeleaf with proper escaping
    public class good_case_10 {
        private final TemplateEngine templateEngine;
        
// {fact rule=autoescape-disabled@v1.0 defects=0}
        public good_case_10(TemplateEngine templateEngine) {
            this.templateEngine = templateEngine;
        }
        
        public String renderUserProfileSafe(HttpServletRequest request) {
            String bio = request.getParameter("bio");
            Context context = new Context();
            // ok: java-cross-site-scripting-ide
            context.setVariable("userBio", bio);
            // Thymeleaf escapes by default in ${...} expressions
            return templateEngine.process("profile", context);
        }
    }
// {/fact}

    // Good case 11: FreeMarker template with proper escaping
    public class good_case_11 {
        public void processTemplateSafe(HttpServletRequest request, PrintWriter out) throws IOException, TemplateException {
            String title = request.getParameter("title");
            Configuration cfg = new Configuration(Configuration.VERSION_2_3_29);
            cfg.setOutputEncoding("UTF-8");
            Template template = cfg.getTemplate("page.ftl");
            java.util.Map<String, Object> root = new java.util.HashMap<>();
            // ok: java-cross-site-scripting-ide
            root.put("pageTitle", title);
            // Using FreeMarker's built-in escaping with ?html in the template
            template.process(root, out);
        }
    }

    // Good case 12: Apache Wicket with proper escaping
    public class good_case_12 extends WebPage {
// {fact rule=autoescape-disabled@v1.0 defects=0}
        public good_case_12(PageParameters parameters) {
            super(parameters);
            String message = parameters.get("message").toString();
            // ok: java-cross-site-scripting-ide
            add(new Label("messageLabel", message));
            // Wicket escapes by default when setEscapeModelStrings is not set to false
        }
    }
// {/fact}

    // Good case 13: Velocity template with escaped user input
    public class good_case_13 {
        public void renderTemplateSafe(HttpServletRequest request, PrintWriter writer) {
            String username = request.getParameter("username");
            VelocityEngine ve = new VelocityEngine();
            ve.init();
            VelocityContext context = new VelocityContext();
            // ok: java-cross-site-scripting-ide
            context.put("username", StringEscapeUtils.escapeHtml4(username));
            org.apache.velocity.Template t = ve.getTemplate("welcome.vm");
            t.merge(context, writer);
        }
    }

    // Good case 14: Struts 2 with escaped user input
    public class good_case_14 extends ActionSupport {
        private String userInput;
        private String htmlOutput;
        
        public String execute() {
            userInput = ServletActionContext.getRequest().getParameter("input");
            // ok: java-cross-site-scripting-ide
            htmlOutput = "<div class='user-content'>" + StringEscapeUtils.escapeHtml4(userInput) + "</div>";
            return SUCCESS;
        }
        
        public String getHtmlOutput() {
            return htmlOutput;
        }
    }

    // Good case 15: Apache Tapestry with proper escaping
    public class good_case_15 {
        @Property
        private String content;
        
        @Inject
        private AjaxResponseRenderer ajaxResponseRenderer;
        
        @OnEvent(value = "displayContentSafe")
        void onDisplayContentSafe(@RequestParameter("content") String userContent) {
            // ok: java-cross-site-scripting-ide
            content = HtmlEscapers.htmlEscaper().escape(userContent);
        }
    }
}