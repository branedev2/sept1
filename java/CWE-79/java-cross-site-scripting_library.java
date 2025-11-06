import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.ui.Model;
import org.owasp.encoder.Encode;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.apache.wicket.markup.html.WebPage;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.request.mapper.parameter.PageParameters;
import org.apache.struts2.ServletActionContext;
import com.opensymphony.xwork2.ActionSupport;
import spark.Request;
import spark.Response;
import spark.Spark;
import play.mvc.Controller;
import play.mvc.Result;
import play.mvc.Http;
import io.javalin.Javalin;
import io.javalin.http.Context;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import ratpack.server.RatpackServer;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinRequest;
import org.apache.tapestry5.annotations.Property;
import org.apache.tapestry5.annotations.OnEvent;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.tapestry5.services.Request;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.apache.commons.text.StringEscapeUtils;
import org.unbescape.html.HtmlEscape;
import com.google.common.html.HtmlEscapers;
import org.apache.commons.lang3.StringUtils;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.freemarker.FreeMarkerConfigurer;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;
import java.io.StringWriter;

// Security Issue: Cross-Site Scripting (XSS) vulnerabilities in Java web applications

// True Positive Examples (Vulnerable/Insecure Code)

public class XSSVulnerabilities {

    // Using Java Servlets
// {fact rule=autoescape-disabled@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("userInput");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-cross-site-scripting
        out.println("<html><body>Your input: " + userInput + "</body></html>");
    }

    // Using Spring MVC
    @Controller
    public class bad_case_2 {
        @GetMapping("/greet")
        @ResponseBody
        public String greetUser(@RequestParam String name) {
            // ruleid: java-cross-site-scripting
            return "<h1>Hello, " + name + "!</h1>";
        }
    }

    // Using Apache Wicket
    public class bad_case_3 extends WebPage {
        public bad_case_3(PageParameters parameters) {
            String userComment = parameters.get("comment").toString();
            
            // ruleid: java-cross-site-scripting
            add(new Label("commentLabel", userComment).setEscapeModelStrings(false));
        }
    }

    // Using Apache Struts 2
    public class bad_case_4 extends ActionSupport {
        public String execute() throws Exception {
            HttpServletRequest request = ServletActionContext.getRequest();
            HttpServletResponse response = ServletActionContext.getResponse();
            
            String userInput = request.getParameter("message");
            PrintWriter out = response.getWriter();
            
            // ruleid: java-cross-site-scripting
            out.println("<div class='message'>" + userInput + "</div>");
            
            return SUCCESS;
        }
    }

    // Using Spark Java
    public void bad_case_5() {
        Spark.get("/hello", (Request req, Response res) -> {
            String name = req.queryParams("name");
            
            // ruleid: java-cross-site-scripting
            return "<h1>Hello, " + name + "!</h1>";
        });
    }

    // Using Play Framework
    public class bad_case_6 extends Controller {
        public Result showMessage(Http.Request request) {
            String message = request.getQueryString("message");
            
            // ruleid: java-cross-site-scripting
            return ok("<div>" + message + "</div>").as("text/html");
        }
    }

    // Using Javalin
    public void bad_case_7() {
        Javalin app = Javalin.create().start(7000);
        app.get("/echo", ctx -> {
            String input = ctx.queryParam("input");
            
            // ruleid: java-cross-site-scripting
            ctx.html("<p>You said: " + input + "</p>");
        });
    }

    // Using Ratpack
    public void bad_case_8() throws Exception {
        RatpackServer.start(server -> server
            .handlers(chain -> chain
                .get("echo", ctx -> {
                    String input = ctx.getRequest().getQueryParams().get("input");
                    
                    // ruleid: java-cross-site-scripting
                    ctx.getResponse().send("text/html", "<p>Echo: " + input + "</p>");
                })
            )
        );
    }

    // Using Vert.x
    public void bad_case_9() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        router.get("/echo").handler(rc -> {
            String input = rc.request().getParam("input");
            
            // ruleid: java-cross-site-scripting
            rc.response().putHeader("content-type", "text/html").end("<div>" + input + "</div>");
        });
        
        vertx.createHttpServer().requestHandler(router).listen(8080);
    }

    // Using Vaadin
    @Route("echo")
    public class bad_case_10 extends VerticalLayout {
        public bad_case_10() {
            String userInput = VaadinRequest.getCurrent().getParameter("input");
            Div div = new Div();
            
            // ruleid: java-cross-site-scripting
            div.getElement().setProperty("innerHTML", userInput);
            add(div);
        }
    }

    // Using Apache Tapestry
    public class bad_case_11 {
        @Property
        private String message;
        
        @Inject
        private Request request;
        
        @OnEvent
        void onActivate() {
            message = request.getParameter("message");
        }
        
        public String getUnsafeMessage() {
            // ruleid: java-cross-site-scripting
            return "<div>" + message + "</div>";
        }
    }

    // Using Thymeleaf outside of Spring
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("input");
        
        TemplateEngine templateEngine = new TemplateEngine();
        Context context = new Context();
        
        // ruleid: java-cross-site-scripting
        context.setVariable("userMessage", userInput);
        String output = templateEngine.process("<div th:utext=\"${userMessage}\"></div>", context);
        
        response.getWriter().write(output);
    }

    // Using FreeMarker
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException, TemplateException {
        String userInput = request.getParameter("input");
        
        Configuration cfg = new Configuration(Configuration.VERSION_2_3_30);
        Template template = cfg.getTemplate("template.ftl");
        
        Map<String, Object> root = new HashMap<>();
        // ruleid: java-cross-site-scripting
        root.put("message", userInput);
        
        StringWriter writer = new StringWriter();
        template.process(root, writer);
        
        response.getWriter().write(writer.toString());
        // Note: The vulnerability occurs when the FreeMarker template uses ${message} without the ?html directive
    }

    // Using JAX-RS (Jersey)
    @Path("/api")
    public class bad_case_14 {
        @GET
        @Path("/echo")
        public Response echoMessage(@QueryParam("message") String message) {
            // ruleid: java-cross-site-scripting
            return Response.ok("<div>" + message + "</div>", "text/html").build();
        }
    }

    // Using Spring MVC with ModelAndView
    @Controller
    public class bad_case_15 {
        @GetMapping("/welcome")
        public ModelAndView welcome(@RequestParam String name) {
            ModelAndView modelAndView = new ModelAndView("welcome");
            
            // ruleid: java-cross-site-scripting
            modelAndView.addObject("welcomeMessage", "<h2>Welcome " + name + "!</h2>");
            // Note: The vulnerability occurs when the JSP uses ${welcomeMessage} without escaping
            
            return modelAndView;
        }
    }

    // True Negative Examples (Safe/Secure Code)

    // Using Java Servlets with OWASP Encoder
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("userInput");
        PrintWriter out = response.getWriter();
        
        // ok: java-cross-site-scripting
        out.println("<html><body>Your input: " + Encode.forHtml(userInput) + "</body></html>");
    }

    // Using Spring MVC with escaping
    @Controller
    public class good_case_2 {
        @GetMapping("/greet")
        @ResponseBody
        public String greetUser(@RequestParam String name) {
            // ok: java-cross-site-scripting
            return "<h1>Hello, " + Encode.forHtml(name) + "!</h1>";
        }
    }

    // Using Apache Wicket with proper escaping
    public class good_case_3 extends WebPage {
        public good_case_3(PageParameters parameters) {
            String userComment = parameters.get("comment").toString();
            
            // ok: java-cross-site-scripting
            add(new Label("commentLabel", userComment).setEscapeModelStrings(true));
        }
    }

    // Using Apache Struts 2 with StringEscapeUtils
    public class good_case_4 extends ActionSupport {
        public String execute() throws Exception {
            HttpServletRequest request = ServletActionContext.getRequest();
            HttpServletResponse response = ServletActionContext.getResponse();
            
            String userInput = request.getParameter("message");
            PrintWriter out = response.getWriter();
            
            // ok: java-cross-site-scripting
            out.println("<div class='message'>" + StringEscapeUtils.escapeHtml4(userInput) + "</div>");
            
            return SUCCESS;
        }
    }

    // Using Spark Java with OWASP Encoder
    public void good_case_5() {
        Spark.get("/hello", (Request req, Response res) -> {
            String name = req.queryParams("name");
            
            // ok: java-cross-site-scripting
            return "<h1>Hello, " + Encode.forHtml(name) + "!</h1>";
        });
    }

    // Using Play Framework with escaping
    public class good_case_6 extends Controller {
        public Result showMessage(Http.Request request) {
            String message = request.getQueryString("message");
            
            // ok: java-cross-site-scripting
            return ok("<div>" + HtmlEscape.escapeHtml5(message) + "</div>").as("text/html");
        }
    }

    // Using Javalin with JSoup sanitization
    public void good_case_7() {
        Javalin app = Javalin.create().start(7000);
        app.get("/echo", ctx -> {
            String input = ctx.queryParam("input");
            
            // ok: java-cross-site-scripting
            ctx.html("<p>You said: " + Jsoup.clean(input, Safelist.basic()) + "</p>");
        });
    }

    // Using Ratpack with Google Guava HtmlEscapers
    public void good_case_8() throws Exception {
        RatpackServer.start(server -> server
            .handlers(chain -> chain
                .get("echo", ctx -> {
                    String input = ctx.getRequest().getQueryParams().get("input");
                    
                    // ok: java-cross-site-scripting
                    ctx.getResponse().send("text/html", "<p>Echo: " + HtmlEscapers.htmlEscaper().escape(input) + "</p>");
                })
            )
        );
    }

    // Using Vert.x with StringEscapeUtils
    public void good_case_9() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        router.get("/echo").handler(rc -> {
            String input = rc.request().getParam("input");
            
            // ok: java-cross-site-scripting
            rc.response().putHeader("content-type", "text/html").end("<div>" + StringEscapeUtils.escapeHtml4(input) + "</div>");
        });
        
        vertx.createHttpServer().requestHandler(router).listen(8080);
    }

    // Using Vaadin safely
    @Route("echo")
    public class good_case_10 extends VerticalLayout {
        public good_case_10() {
            String userInput = VaadinRequest.getCurrent().getParameter("input");
            Div div = new Div();
            
            // ok: java-cross-site-scripting
            div.setText(userInput); // Vaadin's setText method automatically escapes HTML
            add(div);
        }
    }

    // Using Apache Tapestry with escaping
    public class good_case_11 {
        @Property
        private String message;
        
        @Inject
        private Request request;
        
        @OnEvent
        void onActivate() {
            message = request.getParameter("message");
        }
        
        public String getSafeMessage() {
            // ok: java-cross-site-scripting
            return StringEscapeUtils.escapeHtml4(message);
        }
    }

    // Using Thymeleaf outside of Spring with proper escaping
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("input");
        
        TemplateEngine templateEngine = new TemplateEngine();
        Context context = new Context();
        
        // ok: java-cross-site-scripting
        context.setVariable("userMessage", userInput);
        String output = templateEngine.process("<div th:text=\"${userMessage}\"></div>", context);
        // Note: th:text automatically escapes HTML, unlike th:utext
        
        response.getWriter().write(output);
    }

    // Using FreeMarker with proper escaping
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException, TemplateException {
        String userInput = request.getParameter("input");
        
        Configuration cfg = new Configuration(Configuration.VERSION_2_3_30);
        Template template = cfg.getTemplate("template.ftl");
        
        Map<String, Object> root = new HashMap<>();
        // ok: java-cross-site-scripting
        root.put("message", userInput);
        // Note: The template uses ${message?html} to escape the output
        
        StringWriter writer = new StringWriter();
        template.process(root, writer);
        
        response.getWriter().write(writer.toString());
    }

    // Using JAX-RS (Jersey) with OWASP HTML Sanitizer
    @Path("/api")
    public class good_case_14 {
        @GET
        @Path("/echo")
        public Response echoMessage(@QueryParam("message") String message) {
            PolicyFactory policy = new HtmlPolicyBuilder()
                .allowElements("div", "span", "b", "i", "u")
                .toFactory();
            
            // ok: java-cross-site-scripting
            String sanitized = policy.sanitize(message);
            return Response.ok("<div>" + sanitized + "</div>", "text/html").build();
        }
    }

    // Using Spring MVC with ModelAndView and proper escaping
    @Controller
    public class good_case_15 {
        @GetMapping("/welcome")
        public String welcome(@RequestParam String name, Model model) {
            // ok: java-cross-site-scripting
            model.addAttribute("name", Encode.forHtml(name));
            // Note: Using Thymeleaf's th:text in the template will provide additional escaping
            
            return "welcome";
        }
    }
}
// {/fact}