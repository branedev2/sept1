import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.ui.*;
import org.springframework.web.servlet.*;
import org.apache.struts2.dispatcher.*;
import org.apache.struts2.interceptor.*;
import com.opensymphony.xwork2.*;
import org.apache.wicket.markup.html.*;
import org.apache.wicket.markup.html.basic.*;
import org.apache.wicket.request.mapper.parameter.*;
import org.apache.wicket.*;
import spark.*;
import play.mvc.*;
import play.mvc.Http.*;
import views.html.*;
import ratpack.handling.*;
import ratpack.http.*;
import ratpack.render.*;
import com.vaadin.flow.component.html.*;
import com.vaadin.flow.component.*;
import com.vaadin.flow.router.*;
import io.javalin.*;
import io.javalin.http.*;
import io.micronaut.http.*;
import io.micronaut.http.annotation.*;
import io.micronaut.views.*;
import io.quarkus.qute.*;
import io.quarkus.vertx.web.Route;
import io.vertx.ext.web.RoutingContext;
import org.apache.commons.text.StringEscapeUtils;
import org.owasp.encoder.Encode;
import org.unbescape.html.HtmlEscape;
import com.google.common.html.HtmlEscapers;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.StringTemplateResolver;

// Security Issue: Cross-Site Scripting (XSS) Vulnerabilities in Java Web Applications

// True Positive Examples (Vulnerable/Insecure Code)

public class XssVulnerabilities {

    // Spring MVC example
    @Controller
    public static class BadCase1 {
// {fact rule=autoescape-disabled@v1.0 defects=1}
        @RequestMapping("/spring-xss")
        public String bad_case_1(HttpServletRequest request, Model model) {
            String userInput = request.getParameter("userInput");
            // ruleid: java-cross-site-scripting-exp
            model.addAttribute("userMessage", userInput);
            return "userView";
        }
    }
// {/fact}

    // Java Servlets example
    public static class BadCase2 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String userInput = request.getParameter("comment");
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            out.println("<html><body>");
            // ruleid: java-cross-site-scripting-exp
            out.println("<div>" + userInput + "</div>");
            out.println("</body></html>");
        }
    }

    // Apache Struts 2 example
    public static class BadCase3 extends ActionSupport implements ServletRequestAware {
        private HttpServletRequest request;
        private String message;
        
        public String execute() {
            message = request.getParameter("message");
            return SUCCESS;
        }
        
        public void setServletRequest(HttpServletRequest request) {
            this.request = request;
        }
        
        public String getMessage() {
            // ruleid: java-cross-site-scripting-exp
            return message;
        }
    }

    // Apache Wicket example
    public static class BadCase4 extends WebPage {
        public BadCase4(PageParameters parameters) {
            String userInput = parameters.get("message").toString();
            // ruleid: java-cross-site-scripting-exp
            add(new Label("messageLabel", userInput).setEscapeModelStrings(false));
        }
    }

    // Spark Framework example
// {fact rule=autoescape-disabled@v1.0 defects=1}
    public static void bad_case_5() {
        Spark.get("/spark-xss", (request, response) -> {
            String userInput = request.queryParams("userInput");
            // ruleid: java-cross-site-scripting-exp
            return "<div>" + userInput + "</div>";
        });
    }

    // Play Framework example
    public static class BadCase6 extends Controller {
        public Result bad_case_6(Http.Request request) {
            String userInput = request.getQueryString("userInput");
            // ruleid: java-cross-site-scripting-exp
            return ok(views.html.index.render(userInput)).as("text/html");
        }
    }

    // Ratpack example
    public static void bad_case_7() {
        ratpack.server.RatpackServer.start(server -> server
            .handlers(chain -> chain
                .get("ratpack-xss", ctx -> {
                    String userInput = ctx.getRequest().getQueryParams().get("userInput");
                    // ruleid: java-cross-site-scripting-exp
                    ctx.render(userInput);
                })
            )
        );
    }

    // Vaadin example
    @Route("vaadin-xss")
    public static class BadCase8 extends Component implements HasUrlParameter<String> {
        @Override
        public void setParameter(BeforeEvent event, String parameter) {
            Div div = new Div();
            // ruleid: java-cross-site-scripting-exp
            div.getElement().setProperty("innerHTML", parameter);
            getElement().appendChild(div.getElement());
        }
    }

    // Javalin example
    public static void bad_case_9() {
        Javalin app = Javalin.create().start(7000);
        app.get("/javalin-xss", ctx -> {
            String userInput = ctx.queryParam("userInput");
            // ruleid: java-cross-site-scripting-exp
            ctx.html("<div>" + userInput + "</div>");
        });
    }

    // Micronaut example
    @Controller("/micronaut")
    public static class BadCase10 {
        @Get("/xss")
        public HttpResponse<String> bad_case_10(HttpRequest<?> request) {
            String userInput = request.getParameters().get("userInput");
            // ruleid: java-cross-site-scripting-exp
            return HttpResponse.ok("<div>" + userInput + "</div>").contentType(MediaType.TEXT_HTML);
        }
    }

    // Quarkus with Qute templating example
    public static class BadCase11 {
        @Inject
        Template userTemplate;
        
        @GET
        @Path("/quarkus-xss")
        @Produces(MediaType.TEXT_HTML)
        public TemplateInstance bad_case_11(@QueryParam("userInput") String userInput) {
            // ruleid: java-cross-site-scripting-exp
            return userTemplate.data("message", userInput);
        }
    }

    // Vert.x Web example
    public static class BadCase12 {
        @Route(path = "/vertx-xss")
        public void bad_case_12(RoutingContext rc) {
            String userInput = rc.request().getParam("userInput");
            // ruleid: java-cross-site-scripting-exp
            rc.response().putHeader("content-type", "text/html").end("<div>" + userInput + "</div>");
        }
    }

    // JSP scriptlet example
    public static class BadCase13 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String userInput = request.getParameter("userInput");
            // ruleid: java-cross-site-scripting-exp
            request.setAttribute("userMessage", userInput);
            request.getRequestDispatcher("/WEB-INF/views/message.jsp").forward(request, response);
            // In JSP: <%= userMessage %>
        }
    }

    // Direct JavaScript injection example
    public static class BadCase14 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String userInput = request.getParameter("userInput");
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            // ruleid: java-cross-site-scripting-exp
            out.println("<script>var userMessage = '" + userInput + "';</script>");
        }
    }

    // Custom HTML builder example
    public static class BadCase15 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String userInput = request.getHeader("X-User-Message");
            StringBuilder htmlBuilder = new StringBuilder();
            htmlBuilder.append("<html><body>");
            // ruleid: java-cross-site-scripting-exp
            htmlBuilder.append("<div id='message'>").append(userInput).append("</div>");
            htmlBuilder.append("</body></html>");
            
            response.setContentType("text/html");
            response.getWriter().write(htmlBuilder.toString());
        }
    }

    // True Negative Examples (Safe/Secure Code)

    // Spring MVC with proper escaping
    @Controller
    public static class GoodCase1 {
        @RequestMapping("/spring-xss-safe")
        public String good_case_1(HttpServletRequest request, Model model) {
            String userInput = request.getParameter("userInput");
            // ok: java-cross-site-scripting-exp
            model.addAttribute("userMessage", HtmlEscape.escapeHtml5(userInput));
            return "userView";
        }
    }

    // Java Servlets with OWASP Encoder
    public static class GoodCase2 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String userInput = request.getParameter("comment");
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            out.println("<html><body>");
            // ok: java-cross-site-scripting-exp
            out.println("<div>" + Encode.forHtml(userInput) + "</div>");
            out.println("</body></html>");
        }
    }

    // Apache Struts 2 with escaping
    public static class GoodCase3 extends ActionSupport implements ServletRequestAware {
        private HttpServletRequest request;
        private String message;
        
        public String execute() {
            message = request.getParameter("message");
            return SUCCESS;
        }
        
        public void setServletRequest(HttpServletRequest request) {
            this.request = request;
        }
        
        public String getMessage() {
            // ok: java-cross-site-scripting-exp
            return StringEscapeUtils.escapeHtml4(message);
        }
    }

    // Apache Wicket with proper escaping
    public static class GoodCase4 extends WebPage {
        public GoodCase4(PageParameters parameters) {
            String userInput = parameters.get("message").toString();
            // ok: java-cross-site-scripting-exp
            add(new Label("messageLabel", userInput).setEscapeModelStrings(true));
        }
    }

    // Spark Framework with escaping
    public static void good_case_5() {
        Spark.get("/spark-xss-safe", (request, response) -> {
            String userInput = request.queryParams("userInput");
            // ok: java-cross-site-scripting-exp
            return "<div>" + StringEscapeUtils.escapeHtml4(userInput) + "</div>";
        });
    }

    // Play Framework with escaping
    public static class GoodCase6 extends Controller {
        public Result good_case_6(Http.Request request) {
            String userInput = request.getQueryString("userInput");
            // ok: java-cross-site-scripting-exp
            return ok(views.html.index.render(HtmlEscapers.htmlEscaper().escape(userInput))).as("text/html");
        }
    }

    // Ratpack with escaping
    public static void good_case_7() {
        ratpack.server.RatpackServer.start(server -> server
            .handlers(chain -> chain
                .get("ratpack-xss-safe", ctx -> {
                    String userInput = ctx.getRequest().getQueryParams().get("userInput");
                    // ok: java-cross-site-scripting-exp
                    ctx.render(HtmlEscapers.htmlEscaper().escape(userInput));
                })
            )
        );
    }

    // Vaadin with proper text content
    @Route("vaadin-xss-safe")
    public static class GoodCase8 extends Component implements HasUrlParameter<String> {
        @Override
        public void setParameter(BeforeEvent event, String parameter) {
            Div div = new Div();
            // ok: java-cross-site-scripting-exp
            div.setText(parameter); // Vaadin automatically escapes text content
            getElement().appendChild(div.getElement());
        }
    }

    // Javalin with escaping
    public static void good_case_9() {
        Javalin app = Javalin.create().start(7000);
        app.get("/javalin-xss-safe", ctx -> {
            String userInput = ctx.queryParam("userInput");
            // ok: java-cross-site-scripting-exp
            ctx.html("<div>" + StringEscapeUtils.escapeHtml4(userInput) + "</div>");
        });
    }

    // Micronaut with escaping
    @Controller("/micronaut")
    public static class GoodCase10 {
        @Get("/xss-safe")
        public HttpResponse<String> good_case_10(HttpRequest<?> request) {
            String userInput = request.getParameters().get("userInput");
            // ok: java-cross-site-scripting-exp
            return HttpResponse.ok("<div>" + HtmlEscape.escapeHtml5(userInput) + "</div>").contentType(MediaType.TEXT_HTML);
        }
    }

    // Quarkus with Qute templating and safe rendering
    public static class GoodCase11 {
        @Inject
        Template userTemplate;
        
        @GET
        @Path("/quarkus-xss-safe")
        @Produces(MediaType.TEXT_HTML)
        public TemplateInstance good_case_11(@QueryParam("userInput") String userInput) {
            // ok: java-cross-site-scripting-exp
            return userTemplate.data("message", userInput); // Qute escapes by default when using {message} in template
        }
    }

    // Vert.x Web with escaping
    public static class GoodCase12 {
        @Route(path = "/vertx-xss-safe")
        public void good_case_12(RoutingContext rc) {
            String userInput = rc.request().getParam("userInput");
            // ok: java-cross-site-scripting-exp
            rc.response().putHeader("content-type", "text/html").end("<div>" + StringEscapeUtils.escapeHtml4(userInput) + "</div>");
        }
    }

    // JSP with JSTL escaping
    public static class GoodCase13 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String userInput = request.getParameter("userInput");
            // ok: java-cross-site-scripting-exp
            request.setAttribute("userMessage", StringEscapeUtils.escapeHtml4(userInput));
            request.getRequestDispatcher("/WEB-INF/views/message.jsp").forward(request, response);
            // In JSP: ${userMessage} (JSTL escapes by default)
        }
    }

    // JavaScript safe injection with escaping
    public static class GoodCase14 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String userInput = request.getParameter("userInput");
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            // ok: java-cross-site-scripting-exp
            out.println("<script>var userMessage = '" + 
                userInput.replace("\\", "\\\\").replace("'", "\\'").replace("\"", "\\\"") + 
                "';</script>");
        }
    }

    // Using JSoup for HTML sanitization
    public static class GoodCase15 extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            String userInput = request.getHeader("X-User-Message");
            StringBuilder htmlBuilder = new StringBuilder();
            htmlBuilder.append("<html><body>");
            // ok: java-cross-site-scripting-exp
            htmlBuilder.append("<div id='message'>").append(Jsoup.clean(userInput, Safelist.basic())).append("</div>");
            htmlBuilder.append("</body></html>");
            
            response.setContentType("text/html");
            response.getWriter().write(htmlBuilder.toString());
        }
    }
}
// {/fact}