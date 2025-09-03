import javax.servlet.http.*;
import javax.servlet.*;
import java.io.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import org.apache.struts2.dispatcher.SessionMap;
import org.apache.struts2.interceptor.SessionAware;
import java.util.Map;
import org.apache.wicket.protocol.http.WebSession;
import org.apache.wicket.request.Request;
import org.apache.wicket.request.cycle.RequestCycle;
import org.apache.wicket.request.mapper.parameter.PageParameters;
import org.apache.tapestry5.services.Request;
import org.apache.tapestry5.services.Response;
import org.apache.tapestry5.services.Session;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;
import play.mvc.Controller;
import play.mvc.Http;
import play.mvc.Result;
import spark.Session;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinResponse;
import com.vaadin.flow.server.VaadinSession;
import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.ContainerResponse;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.servlet.ShiroHttpServletResponse;
import org.apache.shiro.web.session.HttpServletSession;
import io.javalin.http.Context;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import ratpack.http.Request;
import ratpack.http.Response;
import ratpack.session.Session;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.session.Session;

// Security Issue: URL Rewriting vulnerability (CWE-200)
// This occurs when session IDs are included in URLs, making them visible to third parties

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
    HttpSession session = request.getSession();
    String sessionId = session.getId();
    String targetUrl = request.getParameter("targetUrl");
    
    // ruleid: java-url-rewriting
    String urlWithSession = response.encodeURL(targetUrl);
    response.sendRedirect(urlWithSession);
}

public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
    HttpSession session = request.getSession(true);
    String productId = request.getParameter("productId");
    
    // ruleid: java-url-rewriting
    String encodedUrl = response.encodeRedirectURL("/product?id=" + productId);
    response.sendRedirect(encodedUrl);
}

@Controller
public class bad_case_3 {
    @GetMapping("/checkout")
    public void processCheckout(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession();
        String orderId = request.getParameter("orderId");
        
        // ruleid: java-url-rewriting
        String encodedUrl = response.encodeURL("/payment?order=" + orderId);
        response.getWriter().write("<a href='" + encodedUrl + "'>Proceed to payment</a>");
    }
}

public class bad_case_4 implements SessionAware {
    private Map<String, Object> sessionMap;
    
    public String execute() {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        
        // ruleid: java-url-rewriting
        String url = response.encodeURL("/dashboard");
        return "success";
    }
    
    @Override
    public void setSession(Map<String, Object> session) {
        this.sessionMap = session;
    }
}

public class bad_case_5 extends org.apache.wicket.markup.html.WebPage {
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    public bad_case_5(PageParameters parameters) {
        super(parameters);
        
        org.apache.wicket.protocol.http.WebResponse response = 
            (org.apache.wicket.protocol.http.WebResponse)RequestCycle.get().getResponse();
        
        // ruleid: java-url-rewriting
        String encodedUrl = response.encodeURL("/profile");
        add(new org.apache.wicket.markup.html.basic.Label("url", encodedUrl));
    }
}
// {/fact}

public class bad_case_6 {
    public void process(org.apache.tapestry5.services.Request request, 
                       org.apache.tapestry5.services.Response response) {
        org.apache.tapestry5.services.Session session = request.getSession(true);
        
        // ruleid: java-url-rewriting
        String encodedUrl = response.encodeURL("/dashboard");
        response.sendRedirect(encodedUrl);
    }
}

public class bad_case_7 {
    public void handleRequest(org.jboss.resteasy.spi.HttpRequest request, 
                             org.jboss.resteasy.spi.HttpResponse response) {
        
        // ruleid: java-url-rewriting
        String encodedUrl = response.encodeURL("/account");
        response.sendRedirect(encodedUrl);
    }
}

public class bad_case_8 extends play.mvc.Controller {
    public Result index(Http.Request request) {
        Http.Session session = request.session();
        
        // ruleid: java-url-rewriting
        String encodedUrl = encodeURL(request, "/settings");
        return redirect(encodedUrl);
    }
    
    private String encodeURL(Http.Request request, String url) {
        return url + ";jsessionid=" + request.session().get("sessionId").orElse("");
    }
}

public class bad_case_9 implements spark.Route {
    @Override
    public Object handle(spark.Request request, spark.Response response) {
        spark.Session session = request.session(true);
        
        // ruleid: java-url-rewriting
        String encodedUrl = encodeURL(session, "/dashboard");
        response.redirect(encodedUrl);
        return null;
    }
    
    private String encodeURL(spark.Session session, String url) {
        return url + ";jsessionid=" + session.id();
    }
}

public class bad_case_10 {
    public void processRequest(VaadinRequest request, VaadinResponse response) {
        VaadinSession session = request.getSession();
        
        // ruleid: java-url-rewriting
        String encodedUrl = response.encodeURL("/user/profile");
        response.sendRedirect(encodedUrl);
    }
}

public class bad_case_11 {
    public void handleRequest(ContainerRequest request, ContainerResponse response) {
        javax.servlet.http.HttpServletResponse httpResponse = 
            (javax.servlet.http.HttpServletResponse)response.getContainerResponse();
        
        // ruleid: java-url-rewriting
        String encodedUrl = httpResponse.encodeURL("/api/data");
        response.setEntity(encodedUrl);
    }
}

public class bad_case_12 {
    public void processRequest(ShiroHttpServletRequest request, ShiroHttpServletResponse response) throws IOException {
        HttpServletSession session = request.getSession();
        
        // ruleid: java-url-rewriting
        String encodedUrl = response.encodeURL("/secure/dashboard");
        response.sendRedirect(encodedUrl);
    }
}

public class bad_case_13 implements io.javalin.http.Handler {
    @Override
    public void handle(io.javalin.http.Context ctx) {
        // ruleid: java-url-rewriting
        String encodedUrl = encodeURL(ctx, "/user/settings");
        ctx.redirect(encodedUrl);
    }
    
    private String encodeURL(io.javalin.http.Context ctx, String url) {
        return url + ";jsessionid=" + ctx.req.getSession().getId();
    }
}

@io.micronaut.http.annotation.Controller("/api")
public class bad_case_14 {
    @Get("/redirect")
    public MutableHttpResponse<?> redirect(io.micronaut.http.HttpRequest<?> request) {
        // ruleid: java-url-rewriting
        String encodedUrl = encodeURL(request, "/dashboard");
        return HttpResponse.redirect(io.micronaut.http.uri.URI.create(encodedUrl));
    }
    
    private String encodeURL(io.micronaut.http.HttpRequest<?> request, String url) {
        return url + ";jsessionid=" + request.getHeaders().get("Cookie");
    }
}

public class bad_case_15 implements Handler {
    @Override
    public void handle(ratpack.handling.Context ctx) {
        ratpack.http.Request request = ctx.getRequest();
        ratpack.http.Response response = ctx.getResponse();
        
        // ruleid: java-url-rewriting
        String encodedUrl = encodeURL(ctx, "/account/profile");
        response.sendRedirect(encodedUrl);
    }
    
    private String encodeURL(ratpack.handling.Context ctx, String url) {
        return url + ";jsessionid=" + ctx.get(ratpack.session.Session.class).getId();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
    HttpSession session = request.getSession();
    String targetUrl = request.getParameter("targetUrl");
    
    // ok: java-url-rewriting
    response.sendRedirect(targetUrl);
}

public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
    HttpSession session = request.getSession(true);
    String productId = request.getParameter("productId");
    
    // Using cookies for session tracking instead of URL rewriting
    // ok: java-url-rewriting
    response.sendRedirect("/product?id=" + productId);
}

@Controller
public class good_case_3 {
    @GetMapping("/checkout")
    public void processCheckout(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession();
        String orderId = request.getParameter("orderId");
        
        // ok: java-url-rewriting
        String url = "/payment?order=" + orderId;
        response.getWriter().write("<a href='" + url + "'>Proceed to payment</a>");
    }
}

public class good_case_4 implements SessionAware {
    private Map<String, Object> sessionMap;
    
    public String execute() {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        
        // Using session cookies instead of URL rewriting
        // ok: java-url-rewriting
        request.getSession(true);
        return "success";
    }
    
    @Override
    public void setSession(Map<String, Object> session) {
        this.sessionMap = session;
    }
}

public class good_case_5 extends org.apache.wicket.markup.html.WebPage {
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    public good_case_5(PageParameters parameters) {
        super(parameters);
        
        // Using Wicket's built-in session management (cookie-based)
        // ok: java-url-rewriting
        String url = "/profile";
        add(new org.apache.wicket.markup.html.basic.Label("url", url));
    }
}
// {/fact}

public class good_case_6 {
    public void process(org.apache.tapestry5.services.Request request, 
                       org.apache.tapestry5.services.Response response) {
        org.apache.tapestry5.services.Session session = request.getSession(true);
        
        // Using cookie-based session tracking
        // ok: java-url-rewriting
        response.sendRedirect("/dashboard");
    }
}

public class good_case_7 {
    public void handleRequest(org.jboss.resteasy.spi.HttpRequest request, 
                             org.jboss.resteasy.spi.HttpResponse response) {
        
        // Using cookie-based session tracking
        // ok: java-url-rewriting
        response.sendRedirect("/account");
    }
}

public class good_case_8 extends play.mvc.Controller {
    public Result index(Http.Request request) {
        Http.Session session = request.session();
        
        // Using Play Framework's built-in session management (cookie-based)
        // ok: java-url-rewriting
        return redirect("/settings");
    }
}

public class good_case_9 implements spark.Route {
    @Override
    public Object handle(spark.Request request, spark.Response response) {
        spark.Session session = request.session(true);
        
        // Using Spark's built-in session management (cookie-based)
        // ok: java-url-rewriting
        response.redirect("/dashboard");
        return null;
    }
}

public class good_case_10 {
    public void processRequest(VaadinRequest request, VaadinResponse response) {
        VaadinSession session = request.getSession();
        
        // Using Vaadin's built-in session management
        // ok: java-url-rewriting
        response.sendRedirect("/user/profile");
    }
}

public class good_case_11 {
    public void handleRequest(ContainerRequest request, ContainerResponse response) {
        // Using Jersey's built-in session management (cookie-based)
        // ok: java-url-rewriting
        response.setEntity("/api/data");
    }
}

public class good_case_12 {
    public void processRequest(ShiroHttpServletRequest request, ShiroHttpServletResponse response) throws IOException {
        HttpServletSession session = request.getSession();
        
        // Using Shiro's built-in session management (cookie-based)
        // ok: java-url-rewriting
        response.sendRedirect("/secure/dashboard");
    }
}

public class good_case_13 implements io.javalin.http.Handler {
    @Override
    public void handle(io.javalin.http.Context ctx) {
        // Using Javalin's built-in session management (cookie-based)
        // ok: java-url-rewriting
        ctx.redirect("/user/settings");
    }
}

@io.micronaut.http.annotation.Controller("/api")
public class good_case_14 {
    @Get("/redirect")
    public MutableHttpResponse<?> redirect(io.micronaut.http.HttpRequest<?> request) {
        // Using Micronaut's built-in session management (cookie-based)
        // ok: java-url-rewriting
        return HttpResponse.redirect(io.micronaut.http.uri.URI.create("/dashboard"));
    }
}

public class good_case_15 implements Handler {
    @Override
    public void handle(ratpack.handling.Context ctx) {
        ratpack.http.Request request = ctx.getRequest();
        ratpack.http.Response response = ctx.getResponse();
        
        // Using Ratpack's built-in session management (cookie-based)
        // ok: java-url-rewriting
        response.sendRedirect("/account/profile");
    }
}