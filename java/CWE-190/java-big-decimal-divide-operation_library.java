import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;
import org.apache.commons.math3.fraction.BigFraction;
import com.google.common.math.BigIntegerMath;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.apache.struts2.dispatcher.Parameter;
import org.apache.struts2.interceptor.ServletRequestAware;
import javax.servlet.http.HttpServletResponse;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Controller;
import io.vertx.ext.web.RoutingContext;
import io.vertx.core.http.HttpServerRequest;
import spark.Request;
import spark.Response;
import ratpack.handling.Context;
import ratpack.http.Request;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.component.UI;
import io.javalin.http.Context;
import org.jooby.Request;
import org.jooby.Response;
import org.jooby.mvc.Path;
import org.jooby.mvc.GET;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.concurrent.CompletableFuture;
import okhttp3.OkHttpClient;
import okhttp3.Call;
import okhttp3.Callback;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import retrofit2.http.GET;
import retrofit2.http.Query;

// Security Issue: BigDecimal divide operations without proper scale or rounding mode can lead to ArithmeticException or precision issues

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    String numeratorStr = request.getParameter("numerator");
    String denominatorStr = request.getParameter("denominator");
    
    BigDecimal numerator = new BigDecimal(numeratorStr);
    BigDecimal denominator = new BigDecimal(denominatorStr);
    
    // ruleid: java-big-decimal-divide-operation
    BigDecimal result = numerator.divide(denominator); // Can throw ArithmeticException for non-terminating decimal expansions
    
    System.out.println("Result: " + result);
}

@RestController
public class bad_case_2 {
    @GetMapping("/calculate")
    public String calculateRatio(@RequestParam String value1, @RequestParam String value2) {
        BigDecimal bd1 = new BigDecimal(value1);
        BigDecimal bd2 = new BigDecimal(value2);
        
        // ruleid: java-big-decimal-divide-operation
        BigDecimal ratio = bd1.divide(bd2); // No scale or rounding mode specified
        
        return "Calculated ratio: " + ratio.toString();
    }
}

public class bad_case_3 implements ServletRequestAware {
    private HttpServletRequest request;
    
    @Override
    public void setServletRequest(HttpServletRequest request) {
        this.request = request;
    }
    
    public String calculatePercentage() {
        String totalStr = request.getParameter("total");
        String partStr = request.getParameter("part");
        
        BigDecimal total = new BigDecimal(totalStr);
        BigDecimal part = new BigDecimal(partStr);
        
        // ruleid: java-big-decimal-divide-operation
        BigDecimal percentage = part.divide(total).multiply(new BigDecimal("100"));
        
        return percentage.toString();
    }
}

public class bad_case_4 extends play.mvc.Controller {
    public Result calculateInterest() {
        Http.Request request = request();
        String principalStr = request.getQueryString("principal");
        String rateStr = request.getQueryString("rate");
        
        BigDecimal principal = new BigDecimal(principalStr);
        BigDecimal rate = new BigDecimal(rateStr);
        
        // ruleid: java-big-decimal-divide-operation
        BigDecimal interest = principal.multiply(rate).divide(new BigDecimal("100"));
        
        return ok("Interest: " + interest.toString());
    }
}

public class bad_case_5 {
    public void handleVertxRequest(RoutingContext context) {
        HttpServerRequest request = context.request();
        String amount = request.getParam("amount");
        String months = request.getParam("months");
        
        BigDecimal totalAmount = new BigDecimal(amount);
        BigDecimal totalMonths = new BigDecimal(months);
        
        // ruleid: java-big-decimal-divide-operation
        BigDecimal monthlyPayment = totalAmount.divide(totalMonths);
        
        context.response()
               .putHeader("content-type", "text/plain")
               .end("Monthly payment: " + monthlyPayment.toString());
    }
}

public class bad_case_6 {
    public static String handleSparkRequest(spark.Request request, spark.Response response) {
        String dividend = request.queryParams("dividend");
        String divisor = request.queryParams("divisor");
        
        BigDecimal bdDividend = new BigDecimal(dividend);
        BigDecimal bdDivisor = new BigDecimal(divisor);
        
        // ruleid: java-big-decimal-divide-operation
        BigDecimal quotient = bdDividend.divide(bdDivisor);
        
        return "Quotient: " + quotient.toString();
    }
}

public class bad_case_7 {
    public void handleRatpackRequest(Context ctx) {
        ratpack.http.Request request = ctx.getRequest();
        request.getQueryParams().get("price").then(price -> {
            request.getQueryParams().get("quantity").then(quantity -> {
                BigDecimal bdPrice = new BigDecimal(price);
                BigDecimal bdQuantity = new BigDecimal(quantity);
                
                // ruleid: java-big-decimal-divide-operation
                BigDecimal unitPrice = bdPrice.divide(bdQuantity);
                
                ctx.render("Unit price: " + unitPrice.toString());
            });
        });
    }
}

public class bad_case_8 {
    public void vaadinCalculator() {
        VaadinRequest request = VaadinRequest.getCurrent();
        String revenue = request.getParameter("revenue");
        String expenses = request.getParameter("expenses");
        
        BigDecimal bdRevenue = new BigDecimal(revenue);
        BigDecimal bdExpenses = new BigDecimal(expenses);
        
        // ruleid: java-big-decimal-divide-operation
        BigDecimal profitMargin = bdRevenue.subtract(bdExpenses).divide(bdRevenue);
        
        UI.getCurrent().getPage().executeJs("console.log('Profit margin: " + profitMargin + "')");
    }
}

public class bad_case_9 {
    public void handleJavalinRequest(io.javalin.http.Context ctx) {
        String cost = ctx.queryParam("cost");
        String area = ctx.queryParam("area");
        
        BigDecimal bdCost = new BigDecimal(cost);
        BigDecimal bdArea = new BigDecimal(area);
        
        // ruleid: java-big-decimal-divide-operation
        BigDecimal costPerSquareMeter = bdCost.divide(bdArea);
        
        ctx.result("Cost per square meter: " + costPerSquareMeter.toString());
    }
}

public class bad_case_10 {
    @Path("/tax")
    public class TaxCalculator {
        @GET
        public String calculateTax(org.jooby.Request req) {
            String income = req.param("income").value();
            String deduction = req.param("deduction").value();
            
            BigDecimal bdIncome = new BigDecimal(income);
            BigDecimal bdDeduction = new BigDecimal(deduction);
            
            // ruleid: java-big-decimal-divide-operation
            BigDecimal taxRate = bdDeduction.divide(bdIncome);
            
            return "Effective tax rate: " + taxRate.toString();
        }
    }
}

public class bad_case_11 {
    public String processApacheHttpRequest() throws IOException {
        HttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://api.example.com/values?num1=100&num2=3");
        HttpResponse response = httpClient.execute(request);
        
        String responseBody = EntityUtils.toString(response.getEntity());
        ObjectMapper mapper = new ObjectMapper();
        JsonNode rootNode = mapper.readTree(responseBody);
        
        String num1 = rootNode.get("num1").asText();
        String num2 = rootNode.get("num2").asText();
        
        BigDecimal bdNum1 = new BigDecimal(num1);
        BigDecimal bdNum2 = new BigDecimal(num2);
        
        // ruleid: java-big-decimal-divide-operation
        BigDecimal result = bdNum1.divide(bdNum2);
        
        return "Result: " + result.toString();
    }
}

public class bad_case_12 {
    public CompletableFuture<String> processJavaHttpRequest() {
        java.net.http.HttpClient client = java.net.http.HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.example.com/data?x=10&y=3"))
                .build();
                
        return client.sendAsync(request, BodyHandlers.ofString())
                .thenApply(response -> {
                    try {
                        ObjectMapper mapper = new ObjectMapper();
                        JsonNode rootNode = mapper.readTree(response.body());
                        
                        String x = rootNode.get("x").asText();
                        String y = rootNode.get("y").asText();
                        
                        BigDecimal bdX = new BigDecimal(x);
                        BigDecimal bdY = new BigDecimal(y);
                        
                        // ruleid: java-big-decimal-divide-operation
                        BigDecimal result = bdX.divide(bdY);
                        
                        return "Result: " + result.toString();
                    } catch (Exception e) {
                        return "Error: " + e.getMessage();
                    }
                });
    }
}

public class bad_case_13 {
    public void processOkHttpRequest() {
        OkHttpClient client = new OkHttpClient();
        okhttp3.Request request = new okhttp3.Request.Builder()
                .url("https://api.example.com/metrics?value=100&count=7")
                .build();
                
        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                e.printStackTrace();
            }
            
            @Override
            public void onResponse(Call call, okhttp3.Response response) throws IOException {
                String responseBody = response.body().string();
                try {
                    ObjectMapper mapper = new ObjectMapper();
                    JsonNode rootNode = mapper.readTree(responseBody);
                    
                    String value = rootNode.get("value").asText();
                    String count = rootNode.get("count").asText();
                    
                    BigDecimal bdValue = new BigDecimal(value);
                    BigDecimal bdCount = new BigDecimal(count);
                    
                    // ruleid: java-big-decimal-divide-operation
                    BigDecimal average = bdValue.divide(bdCount);
                    
                    System.out.println("Average: " + average);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }
}

public class bad_case_14 {
    interface ApiService {
        @GET("stats")
        retrofit2.Call<StatsResponse> getStats(@Query("total") String total, @Query("parts") String parts);
    }
    
    static class StatsResponse {
        public String total;
        public String parts;
    }
    
    public void processRetrofitRequest() {
        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("https://api.example.com/")
                .addConverterFactory(GsonConverterFactory.create())
                .build();
                
        ApiService service = retrofit.create(ApiService.class);
        retrofit2.Call<StatsResponse> call = service.getStats("1000", "3");
        
        call.enqueue(new retrofit2.Callback<StatsResponse>() {
            @Override
            public void onResponse(retrofit2.Call<StatsResponse> call, retrofit2.Response<StatsResponse> response) {
                if (response.isSuccessful() && response.body() != null) {
                    StatsResponse stats = response.body();
                    
                    BigDecimal total = new BigDecimal(stats.total);
                    BigDecimal parts = new BigDecimal(stats.parts);
                    
                    // ruleid: java-big-decimal-divide-operation
                    BigDecimal partValue = total.divide(parts);
                    
                    System.out.println("Part value: " + partValue);
                }
            }
            
            @Override
            public void onFailure(retrofit2.Call<StatsResponse> call, Throwable t) {
                t.printStackTrace();
            }
        });
    }
}

public class bad_case_15 {
    @Controller
    public class FinanceController {
        @GetMapping("/finance/calculate")
        public String calculateFinanceMetrics(HttpServletRequest request, Model model) {
            String investmentStr = request.getParameter("investment");
            String returnsStr = request.getParameter("returns");
            
            BigDecimal investment = new BigDecimal(investmentStr);
            BigDecimal returns = new BigDecimal(returnsStr);
            
            // ruleid: java-big-decimal-divide-operation
            BigDecimal roi = returns.divide(investment);
            
            model.addAttribute("roi", roi);
            return "finance/results";
        }
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    String numeratorStr = request.getParameter("numerator");
    String denominatorStr = request.getParameter("denominator");
    
    BigDecimal numerator = new BigDecimal(numeratorStr);
    BigDecimal denominator = new BigDecimal(denominatorStr);
    
    // ok: java-big-decimal-divide-operation
    BigDecimal result = numerator.divide(denominator, 10, RoundingMode.HALF_UP);
    
    System.out.println("Result: " + result);
}

@RestController
public class good_case_2 {
    @GetMapping("/calculate-safe")
    public String calculateRatio(@RequestParam String value1, @RequestParam String value2) {
        BigDecimal bd1 = new BigDecimal(value1);
        BigDecimal bd2 = new BigDecimal(value2);
        
        // ok: java-big-decimal-divide-operation
        BigDecimal ratio = bd1.divide(bd2, new MathContext(10, RoundingMode.HALF_EVEN));
        
        return "Calculated ratio: " + ratio.toString();
    }
}

public class good_case_3 implements ServletRequestAware {
    private HttpServletRequest request;
    
    @Override
    public void setServletRequest(HttpServletRequest request) {
        this.request = request;
    }
    
    public String calculatePercentage() {
        String totalStr = request.getParameter("total");
        String partStr = request.getParameter("part");
        
        BigDecimal total = new BigDecimal(totalStr);
        BigDecimal part = new BigDecimal(partStr);
        
        // ok: java-big-decimal-divide-operation
        BigDecimal percentage = part.divide(total, 5, RoundingMode.HALF_UP).multiply(new BigDecimal("100"));
        
        return percentage.toString();
    }
}

public class good_case_4 extends play.mvc.Controller {
    public Result calculateInterest() {
        Http.Request request = request();
        String principalStr = request.getQueryString("principal");
        String rateStr = request.getQueryString("rate");
        
        BigDecimal principal = new BigDecimal(principalStr);
        BigDecimal rate = new BigDecimal(rateStr);
        
        // ok: java-big-decimal-divide-operation
        BigDecimal interest = principal.multiply(rate).divide(new BigDecimal("100"), 2, RoundingMode.DOWN);
        
        return ok("Interest: " + interest.toString());
    }
}

public class good_case_5 {
    public void handleVertxRequest(RoutingContext context) {
        HttpServerRequest request = context.request();
        String amount = request.getParam("amount");
        String months = request.getParam("months");
        
        BigDecimal totalAmount = new BigDecimal(amount);
        BigDecimal totalMonths = new BigDecimal(months);
        
        // ok: java-big-decimal-divide-operation
        BigDecimal monthlyPayment = totalAmount.divide(totalMonths, 2, RoundingMode.CEILING);
        
        context.response()
               .putHeader("content-type", "text/plain")
               .end("Monthly payment: " + monthlyPayment.toString());
    }
}

public class good_case_6 {
    public static String handleSparkRequest(spark.Request request, spark.Response response) {
        String dividend = request.queryParams("dividend");
        String divisor = request.queryParams("divisor");
        
        BigDecimal bdDividend = new BigDecimal(dividend);
        BigDecimal bdDivisor = new BigDecimal(divisor);
        
        // ok: java-big-decimal-divide-operation
        BigDecimal quotient = bdDividend.divide(bdDivisor, new MathContext(15));
        
        return "Quotient: " + quotient.toString();
    }
}

public class good_case_7 {
    public void handleRatpackRequest(Context ctx) {
        ratpack.http.Request request = ctx.getRequest();
        request.getQueryParams().get("price").then(price -> {
            request.getQueryParams().get("quantity").then(quantity -> {
                BigDecimal bdPrice = new BigDecimal(price);
                BigDecimal bdQuantity = new BigDecimal(quantity);
                
                // ok: java-big-decimal-divide-operation
                BigDecimal unitPrice = bdPrice.divide(bdQuantity, 4, RoundingMode.HALF_EVEN);
                
                ctx.render("Unit price: " + unitPrice.toString());
            });
        });
    }
}

public class good_case_8 {
    public void vaadinCalculator() {
        VaadinRequest request = VaadinRequest.getCurrent();
        String revenue = request.getParameter("revenue");
        String expenses = request.getParameter("expenses");
        
        BigDecimal bdRevenue = new BigDecimal(revenue);
        BigDecimal bdExpenses = new BigDecimal(expenses);
        
        // ok: java-big-decimal-divide-operation
        BigDecimal profitMargin = bdRevenue.subtract(bdExpenses).divide(bdRevenue, 4, RoundingMode.HALF_UP);
        
        UI.getCurrent().getPage().executeJs("console.log('Profit margin: " + profitMargin + "')");
    }
}

public class good_case_9 {
    public void handleJavalinRequest(io.javalin.http.Context ctx) {
        String cost = ctx.queryParam("cost");
        String area = ctx.queryParam("area");
        
        BigDecimal bdCost = new BigDecimal(cost);
        BigDecimal bdArea = new BigDecimal(area);
        
        // ok: java-big-decimal-divide-operation
        BigDecimal costPerSquareMeter = bdCost.divide(bdArea, 2, RoundingMode.UP);
        
        ctx.result("Cost per square meter: " + costPerSquareMeter.toString());
    }
}

public class good_case_10 {
    @Path("/tax")
    public class TaxCalculator {
        @GET
        public String calculateTax(org.jooby.Request req) {
            String income = req.param("income").value();
            String deduction = req.param("deduction").value();
            
            BigDecimal bdIncome = new BigDecimal(income);
            BigDecimal bdDeduction = new BigDecimal(deduction);
            
            // ok: java-big-decimal-divide-operation
            BigDecimal taxRate = bdDeduction.divide(bdIncome, new MathContext(6, RoundingMode.HALF_DOWN));
            
            return "Effective tax rate: " + taxRate.toString();
        }
    }
}

public class good_case_11 {
    public String processApacheHttpRequest() throws IOException {
        HttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://api.example.com/values?num1=100&num2=3");
        HttpResponse response = httpClient.execute(request);
        
        String responseBody = EntityUtils.toString(response.getEntity());
        ObjectMapper mapper = new ObjectMapper();
        JsonNode rootNode = mapper.readTree(responseBody);
        
        String num1 = rootNode.get("num1").asText();
        String num2 = rootNode.get("num2").asText();
        
        BigDecimal bdNum1 = new BigDecimal(num1);
        BigDecimal bdNum2 = new BigDecimal(num2);
        
        // ok: java-big-decimal-divide-operation
        BigDecimal result = bdNum1.divide(bdNum2, 10, RoundingMode.HALF_EVEN);
        
        return "Result: " + result.toString();
    }
}

public class good_case_12 {
    public CompletableFuture<String> processJavaHttpRequest() {
        java.net.http.HttpClient client = java.net.http.HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.example.com/data?x=10&y=3"))
                .build();
                
        return client.sendAsync(request, BodyHandlers.ofString())
                .thenApply(response -> {
                    try {
                        ObjectMapper mapper = new ObjectMapper();
                        JsonNode rootNode = mapper.readTree(response.body());
                        
                        String x = rootNode.get("x").asText();
                        String y = rootNode.get("y").asText();
                        
                        BigDecimal bdX = new BigDecimal(x);
                        BigDecimal bdY = new BigDecimal(y);
                        
                        // ok: java-big-decimal-divide-operation
                        BigDecimal result = bdX.divide(bdY, 8, RoundingMode.HALF_DOWN);
                        
                        return "Result: " + result.toString();
                    } catch (Exception e) {
                        return "Error: " + e.getMessage();
                    }
                });
    }
}

public class good_case_13 {
    public void processOkHttpRequest() {
        OkHttpClient client = new OkHttpClient();
        okhttp3.Request request = new okhttp3.Request.Builder()
                .url("https://api.example.com/metrics?value=100&count=7")
                .build();
                
        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                e.printStackTrace();
            }
            
            @Override
            public void onResponse(Call call, okhttp3.Response response) throws IOException {
                String responseBody = response.body().string();
                try {
                    ObjectMapper mapper = new ObjectMapper();
                    JsonNode rootNode = mapper.readTree(responseBody);
                    
                    String value = rootNode.get("value").asText();
                    String count = rootNode.get("count").asText();
                    
                    BigDecimal bdValue = new BigDecimal(value);
                    BigDecimal bdCount = new BigDecimal(count);
                    
                    // ok: java-big-decimal-divide-operation
                    BigDecimal average = bdValue.divide(bdCount, 3, RoundingMode.HALF_UP);
                    
                    System.out.println("Average: " + average);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }
}

public class good_case_14 {
    interface ApiService {
        @GET("stats")
        retrofit2.Call<StatsResponse> getStats(@Query("total") String total, @Query("parts") String parts);
    }
    
    static class StatsResponse {
        public String total;
        public String parts;
    }
    
    public void processRetrofitRequest() {
        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("https://api.example.com/")
                .addConverterFactory(GsonConverterFactory.create())
                .build();
                
        ApiService service = retrofit.create(ApiService.class);
        retrofit2.Call<StatsResponse> call = service.getStats("1000", "3");
        
        call.enqueue(new retrofit2.Callback<StatsResponse>() {
            @Override
            public void onResponse(retrofit2.Call<StatsResponse> call, retrofit2.Response<StatsResponse> response) {
                if (response.isSuccessful() && response.body() != null) {
                    StatsResponse stats = response.body();
                    
                    BigDecimal total = new BigDecimal(stats.total);
                    BigDecimal parts = new BigDecimal(stats.parts);
                    
                    // ok: java-big-decimal-divide-operation
                    BigDecimal partValue = total.divide(parts, new MathContext(7));
                    
                    System.out.println("Part value: " + partValue);
                }
            }
            
            @Override
            public void onFailure(retrofit2.Call<StatsResponse> call, Throwable t) {
                t.printStackTrace();
            }
        });
    }
}

public class good_case_15 {
    @Controller
    public class FinanceController {
        @GetMapping("/finance/calculate")
        public String calculateFinanceMetrics(HttpServletRequest request, Model model) {
            String investmentStr = request.getParameter("investment");
            String returnsStr = request.getParameter("returns");
            
            BigDecimal investment = new BigDecimal(investmentStr);
            BigDecimal returns = new BigDecimal(returnsStr);
            
            // ok: java-big-decimal-divide-operation
            BigDecimal roi = returns.divide(investment, 4, RoundingMode.HALF_UP);
            
            model.addAttribute("roi", roi);
            return "finance/results";
        }
    }
}