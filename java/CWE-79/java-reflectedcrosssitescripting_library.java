import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.ui.Model;
import org.apache.struts2.ServletActionContext;
import com.opensymphony.xwork2.ActionSupport;
import spark.Request;
import spark.Response;
import spark.Route;
import play.mvc.Result;
import play.mvc.Controller;
import play.mvc.Http;
import io.javalin.Javalin;
import io.javalin.http.Context;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.router.Route;
import org.apache.wicket.markup.html.WebPage;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.request.mapper.parameter.PageParameters;
import org.apache.commons.text.StringEscapeUtils;
import org.owasp.encoder.Encode;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;
import org.jsoup.Jsoup;
import org.jsoup.safety.Whitelist;
import com.google.common.html.HtmlEscapers;
import org.unbescape.html.HtmlEscape;
import org.apache.commons.lang3.StringUtils;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import freemarker.template.*;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import javax.ws.rs.core.Response;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
import io.quarkus.qute.api.ResourcePath;
import javax.inject.Inject;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

// Security Issue: Reflected Cross-Site Scripting (XSS) Vulnerability

// True Positive Examples (Vulnerable/Insecure Code)

public class ReflectedXSSExamples {

    // Spring MVC example
    @Controller
    public static class bad_case_1 {
        @GetMapping("/search")
        public String search(@RequestParam String query, Model model) {
            // ruleid: java-reflectedcrosssitescripting
            model.addAttribute("searchResult", "<div>Results for: " + query + "</div>");
            return "search";
        }
    }

    // Java Servlet example
    public static class bad_case_2 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String username = request.getParameter("username");
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            out.println("<html><body>");
            // ruleid: java-reflectedcrosssitescripting
            out.println("<h1>Welcome, " + username + "!</h1>");
            out.println("</body></html>");
        }
    }

    // Struts 2 example
    public static class bad_case_3 extends ActionSupport {
        private String message;
        
        public String execute() {
            HttpServletRequest request = ServletActionContext.getRequest();
            message = request.getParameter("message");
            return SUCCESS;
        }
        
        public String getMessage() {
            // ruleid: java-reflectedcrosssitescripting
            return "<p>" + message + "</p>";
        }
    }

    // Spark Java example
    public static class bad_case_4 {
        public void setupRoutes() {
            spark.Spark.get("/profile", (Request req, Response res) -> {
                String name = req.queryParams("name");
                // ruleid: java-reflectedcrosssitescripting
                return "<html><body><h1>Profile for " + name + "</h1></body></html>";
            });
        }
    }

    // Play Framework example
    public static class bad_case_5 extends play.mvc.Controller {
        public Result showUser(Http.Request request) {
            String userId = request.getQueryString("id");
            // ruleid: java-reflectedcrosssitescripting
            return ok("<div>User ID: " + userId + "</div>").as("text/html");
        }
    }

    // Javalin example
    public static class bad_case_6 {
        public void setupApp() {
            Javalin app = Javalin.create().start(7000);
            app.get("/echo", ctx -> {
                String message = ctx.queryParam("message");
                // ruleid: java-reflectedcrosssitescripting
                ctx.html("<div class='message'>" + message + "</div>");
            });
        }
    }

    // Ratpack example
    public static class bad_case_7 implements Handler {
        @Override
        public void handle(ratpack.handling.Context ctx) {
            String input = ctx.getRequest().getQueryParams().get("input");
            // ruleid: java-reflectedcrosssitescripting
            ctx.getResponse().send("text/html", "<p>You said: " + input + "</p>");
        }
    }

    // Vaadin example
    @com.vaadin.flow.router.Route("feedback")
    public static class bad_case_8 extends Div {
// {fact rule=autoescape-disabled@v1.0 defects=1}
        public bad_case_8() {
            String feedback = com.vaadin.flow.component.UI.getCurrent().getLocation().getQueryParameters().getParameters().get("text").get(0);
            H1 header = new H1("Feedback");
            add(header);
            // ruleid: java-reflectedcrosssitescripting
            getElement().setProperty("innerHTML", "<div>Your feedback: " + feedback + "</div>");
        }
    }
// {/fact}

    // Apache Wicket example
    public static class bad_case_9 extends WebPage {
// {fact rule=autoescape-disabled@v1.0 defects=1}
        public bad_case_9(PageParameters parameters) {
            String comment = parameters.get("comment").toString();
            // ruleid: java-reflectedcrosssitescripting
            add(new Label("commentLabel", "<div>" + comment + "</div>").setEscapeModelStrings(false));
        }
    }
// {/fact}

    // JAX-RS example
    @Path("/api")
    public static class bad_case_10 {
        @GET
        @Path("/comment")
        public Response getComment(@QueryParam("text") String text) {
            // ruleid: java-reflectedcrosssitescripting
            return Response.ok("<div class='comment'>" + text + "</div>", "text/html").build();
        }
    }

    // Micronaut example
    @Controller("/micronaut")
    public static class bad_case_11 {
        @Get("/echo{?message}")
        public HttpResponse<String> echo(String message) {
            // ruleid: java-reflectedcrosssitescripting
            return HttpResponse.ok("<div>" + message + "</div>").contentType("text/html");
        }
    }

    // Quarkus with Qute templating example
    public static class bad_case_12 {
        @Inject
        @ResourcePath("templates/message.html")
        Template messageTemplate;

        @GET
        @Path("/message")
        public TemplateInstance getMessage(@QueryParam("content") String content) {
            // ruleid: java-reflectedcrosssitescripting
            return messageTemplate.data("message", "<span>" + content + "</span>");
        }
    }

    // Jetty Handler example
    public static class bad_case_13 extends AbstractHandler {
        public void handle(String target, org.eclipse.jetty.server.Request baseRequest, 
                          javax.servlet.http.HttpServletRequest request, 
                          javax.servlet.http.HttpServletResponse response) throws IOException, ServletException {
            String name = request.getParameter("name");
            response.setContentType("text/html;charset=utf-8");
            response.setStatus(HttpServletResponse.SC_OK);
            baseRequest.setHandled(true);
            // ruleid: java-reflectedcrosssitescripting
            response.getWriter().println("<h1>Hello " + name + "</h1>");
        }
    }

    // Spring WebFlux example
    public static class bad_case_14 {
        public Mono<ServerResponse> handleRequest(ServerRequest request) {
            return ServerResponse.ok()
                .contentType(org.springframework.http.MediaType.TEXT_HTML)
                // ruleid: java-reflectedcrosssitescripting
                .body(Mono.just("<div>Query: " + request.queryParam("q").orElse("") + "</div>"), String.class);
        }
    }

    // Thymeleaf direct string template example
    public static class bad_case_15 {
        public String processTemplate(HttpServletRequest request) {
            String userInput = request.getParameter("input");
            TemplateEngine templateEngine = new TemplateEngine();
            Context context = new Context();
            // ruleid: java-reflectedcrosssitescripting
            String template = "<div>User input: " + userInput + "</div>";
            return templateEngine.process(template, context);
        }
    }

    // True Negative Examples (Safe/Secure Code)

    // Spring MVC with proper escaping
    @Controller
    public static class good_case_1 {
        @GetMapping("/search")
        public String search(@RequestParam String query, Model model) {
            // ok: java-reflectedcrosssitescripting
            model.addAttribute("searchQuery", query);  // Safely passed to model, will be auto-escaped by Thymeleaf
            return "search";
        }
    }

    // Java Servlet with OWASP Encoder
    public static class good_case_2 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String username = request.getParameter("username");
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            out.println("<html><body>");
            // ok: java-reflectedcrosssitescripting
            out.println("<h1>Welcome, " + Encode.forHtml(username) + "!</h1>");
            out.println("</body></html>");
        }
    }

    // Struts 2 with proper escaping
    public static class good_case_3 extends ActionSupport {
        private String message;
        
        public String execute() {
            HttpServletRequest request = ServletActionContext.getRequest();
            message = request.getParameter("message");
            return SUCCESS;
        }
        
        public String getMessage() {
            // ok: java-reflectedcrosssitescripting
            return StringEscapeUtils.escapeHtml4(message);
        }
    }

    // Spark Java with escaping
    public static class good_case_4 {
        public void setupRoutes() {
            spark.Spark.get("/profile", (Request req, Response res) -> {
                String name = req.queryParams("name");
                // ok: java-reflectedcrosssitescripting
                return "<html><body><h1>Profile for " + StringEscapeUtils.escapeHtml4(name) + "</h1></body></html>";
            });
        }
    }

    // Play Framework with safe template
    public static class good_case_5 extends play.mvc.Controller {
        public Result showUser(Http.Request request) {
            String userId = request.getQueryString("id");
            // ok: java-reflectedcrosssitescripting
            return ok(views.html.user.render(userId));  // Using template engine that auto-escapes
        }
    }

    // Javalin with escaping
    public static class good_case_6 {
        public void setupApp() {
            Javalin app = Javalin.create().start(7000);
            app.get("/echo", ctx -> {
                String message = ctx.queryParam("message");
                // ok: java-reflectedcrosssitescripting
                ctx.html("<div class='message'>" + HtmlEscape.escapeHtml5(message) + "</div>");
            });
        }
    }

    // Ratpack with escaping
    public static class good_case_7 implements Handler {
        @Override
        public void handle(ratpack.handling.Context ctx) {
            String input = ctx.getRequest().getQueryParams().get("input");
            // ok: java-reflectedcrosssitescripting
            ctx.getResponse().send("text/html", "<p>You said: " + HtmlEscapers.htmlEscaper().escape(input) + "</p>");
        }
    }

    // Vaadin with proper text handling
    @com.vaadin.flow.router.Route("feedback")
    public static class good_case_8 extends Div {
// {fact rule=autoescape-disabled@v1.0 defects=0}
        public good_case_8() {
            String feedback = com.vaadin.flow.component.UI.getCurrent().getLocation().getQueryParameters().getParameters().get("text").get(0);
            H1 header = new H1("Feedback");
            add(header);
            // ok: java-reflectedcrosssitescripting
            Div feedbackDiv = new Div();
            feedbackDiv.setText("Your feedback: " + feedback);  // setText properly escapes content
            add(feedbackDiv);
        }
    }
// {/fact}

    // Apache Wicket with escaping
    public static class good_case_9 extends WebPage {
// {fact rule=autoescape-disabled@v1.0 defects=0}
        public good_case_9(PageParameters parameters) {
            String comment = parameters.get("comment").toString();
            // ok: java-reflectedcrosssitescripting
            add(new Label("commentLabel", comment));  // Default behavior escapes HTML
        }
    }
// {/fact}

    // JAX-RS with HTML sanitization
    @Path("/api")
    public static class good_case_10 {
        @GET
        @Path("/comment")
        public Response getComment(@QueryParam("text") String text) {
            PolicyFactory policy = Sanitizers.FORMATTING.and(Sanitizers.BLOCKS);
            // ok: java-reflectedcrosssitescripting
            String safeHtml = policy.sanitize(text);
            return Response.ok("<div class='comment'>" + safeHtml + "</div>", "text/html").build();
        }
    }

    // Micronaut with JSoup sanitization
    @Controller("/micronaut")
    public static class good_case_11 {
        @Get("/echo{?message}")
        public HttpResponse<String> echo(String message) {
            // ok: java-reflectedcrosssitescripting
            String clean = Jsoup.clean(message, Whitelist.basic());
            return HttpResponse.ok("<div>" + clean + "</div>").contentType("text/html");
        }
    }

    // Quarkus with proper escaping
    public static class good_case_12 {
        @Inject
        @ResourcePath("templates/message.html")
        Template messageTemplate;

        @GET
        @Path("/message")
        public TemplateInstance getMessage(@QueryParam("content") String content) {
            // ok: java-reflectedcrosssitescripting
            return messageTemplate.data("message", content);  // Qute templates escape by default
        }
    }

    // Jetty Handler with escaping
    public static class good_case_13 extends AbstractHandler {
        public void handle(String target, org.eclipse.jetty.server.Request baseRequest, 
                          javax.servlet.http.HttpServletRequest request, 
                          javax.servlet.http.HttpServletResponse response) throws IOException, ServletException {
            String name = request.getParameter("name");
            response.setContentType("text/html;charset=utf-8");
            response.setStatus(HttpServletResponse.SC_OK);
            baseRequest.setHandled(true);
            // ok: java-reflectedcrosssitescripting
            response.getWriter().println("<h1>Hello " + StringEscapeUtils.escapeHtml4(name) + "</h1>");
        }
    }

    // Spring WebFlux with escaping
    public static class good_case_14 {
        public Mono<ServerResponse> handleRequest(ServerRequest request) {
            return ServerResponse.ok()
                .contentType(org.springframework.http.MediaType.TEXT_HTML)
                // ok: java-reflectedcrosssitescripting
                .body(Mono.just("<div>Query: " + HtmlUtils.htmlEscape(request.queryParam("q").orElse("")) + "</div>"), String.class);
        }
    }

    // Thymeleaf with proper context variable
    public static class good_case_15 {
        public String processTemplate(HttpServletRequest request) {
            String userInput = request.getParameter("input");
            TemplateEngine templateEngine = new TemplateEngine();
            Context context = new Context();
            // ok: java-reflectedcrosssitescripting
            context.setVariable("userInput", userInput);  // Thymeleaf will auto-escape this
            return templateEngine.process("templates/user-input", context);
        }
    }
}