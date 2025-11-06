import org.junit.Test;
import org.junit.jupiter.api.Test as JupiterTest;
import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.*;
import org.testng.annotations.Test as TestNGTest;
import static org.testng.Assert.*;
import org.mockito.Mockito;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.junit.runner.RunWith;
import com.jayway.restassured.RestAssured;
import io.restassured.response.Response;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import java.net.HttpURLConnection;
import java.net.URL;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.javanet.NetHttpTransport;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.seleniumhq.selenium.WebDriver;
import org.seleniumhq.selenium.chrome.ChromeDriver;
import io.vertx.core.Vertx;
import io.vertx.ext.web.client.WebClient;
import io.vertx.core.buffer.Buffer;
import io.vertx.ext.web.client.HttpResponse;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;

// Security Issue: Using Java native assertions (assert keyword) in JUnit tests can lead to unreliable results
// as these assertions may be disabled by default, causing tests to pass silently when assertions are not evaluated.

// True Positive Examples (Vulnerable/Insecure Code)

public class NativeAssertInJUnitTests {

    // True Positive Examples (Vulnerable/Insecure Code)
    
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    @Test
    public void bad_case_1() {
        // Using native assert in a standard JUnit test
        String response = "Hello, World!";
        // ruleid: java-avoid-native-assert-in-junit
        assert response.contains("Hello");
    }
    
    @JupiterTest
    public void bad_case_2() {
        // Using native assert in a JUnit Jupiter test with Spring RestTemplate
        org.springframework.web.client.RestTemplate restTemplate = new org.springframework.web.client.RestTemplate();
        String response = restTemplate.getForObject("https://api.example.com/data", String.class);
        // ruleid: java-avoid-native-assert-in-junit
        assert response != null;
    }
    
    @Test
    public void bad_case_3() {
        // Using native assert in JUnit test with Apache HttpClient
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet request = new HttpGet("https://api.example.com/users");
            org.apache.http.HttpResponse response = httpClient.execute(request);
            String responseBody = EntityUtils.toString(response.getEntity());
            // ruleid: java-avoid-native-assert-in-junit
            assert responseBody.contains("user_id");
        } catch (Exception e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }
    
    @TestNGTest
    public void bad_case_4() {
        // Using native assert in TestNG test with OkHttp
        try {
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                .url("https://api.example.com/products")
                .build();
            okhttp3.Response response = client.newCall(request).execute();
            String responseBody = response.body().string();
            // ruleid: java-avoid-native-assert-in-junit
            assert response.isSuccessful();
        } catch (Exception e) {
            org.testng.Assert.fail("Exception occurred: " + e.getMessage());
        }
    }
    
    @Test
    public void bad_case_5() {
        // Using native assert in JUnit test with Java's HttpURLConnection
        try {
            URL url = new URL("https://api.example.com/status");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            int responseCode = connection.getResponseCode();
            // ruleid: java-avoid-native-assert-in-junit
            assert responseCode == 200;
        } catch (Exception e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }
    
    @Test
    public void bad_case_6() {
        // Using native assert in JUnit test with Retrofit
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build();
        ApiService service = retrofit.create(ApiService.class);
        try {
            retrofit2.Response<User> response = service.getUser(123).execute();
            // ruleid: java-avoid-native-assert-in-junit
            assert response.body() != null;
        } catch (Exception e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }
    
    @Test
    public void bad_case_7() {
        // Using native assert in JUnit test with AWS SDK
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        boolean exists = s3Client.doesBucketExistV2("my-bucket");
        // ruleid: java-avoid-native-assert-in-junit
        assert exists;
    }
    
    @Test
    public void bad_case_8() {
        // Using native assert in JUnit test with Google HTTP Client
        try {
            HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
            HttpRequest request = requestFactory.buildGetRequest(new GenericUrl("https://api.example.com/data"));
            com.google.api.client.http.HttpResponse response = request.execute();
            // ruleid: java-avoid-native-assert-in-junit
            assert response.getStatusCode() == 200;
        } catch (Exception e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }
    
    @Test
    public void bad_case_9() {
        // Using native assert in JUnit test with JSoup
        try {
            Document doc = Jsoup.connect("https://example.com").get();
            String title = doc.title();
            // ruleid: java-avoid-native-assert-in-junit
            assert title.contains("Example");
        } catch (Exception e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }
    
    @Test
    public void bad_case_10() {
        // Using native assert in JUnit test with Selenium
        WebDriver driver = new ChromeDriver();
        driver.get("https://example.com");
        String pageTitle = driver.getTitle();
        // ruleid: java-avoid-native-assert-in-junit
        assert pageTitle.equals("Example Domain");
        driver.quit();
    }
    
    @Test
    public void bad_case_11() {
        // Using native assert in JUnit test with Vert.x WebClient
        Vertx vertx = Vertx.vertx();
        WebClient client = WebClient.create(vertx);
        
        client.get(80, "example.com", "/")
            .send(ar -> {
                if (ar.succeeded()) {
                    HttpResponse<Buffer> response = ar.result();
                    // ruleid: java-avoid-native-assert-in-junit
                    assert response.statusCode() == 200;
                } else {
                    fail("Request failed");
                }
            });
    }
    
    @Test
    public void bad_case_12() {
        // Using native assert in JUnit test with Spring MockMvc
        MockMvc mockMvc;  // Assume this is initialized in setup
        try {
            String result = mockMvc.perform(MockMvcRequestBuilders.get("/api/users"))
                .andReturn()
                .getResponse()
                .getContentAsString();
            // ruleid: java-avoid-native-assert-in-junit
            assert result.contains("userId");
        } catch (Exception e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }
    
    @Test
    public void bad_case_13() {
        // Using native assert in JUnit test with RestAssured
        Response response = RestAssured.get("https://api.example.com/users");
        String responseBody = response.getBody().asString();
        // ruleid: java-avoid-native-assert-in-junit
        assert response.getStatusCode() == 200;
    }
    
    @Test
    public void bad_case_14() {
        // Using native assert in JUnit test with Square's OkHttp
        try {
            com.squareup.okhttp.OkHttpClient client = new com.squareup.okhttp.OkHttpClient();
            com.squareup.okhttp.Request request = new com.squareup.okhttp.Request.Builder()
                .url("https://api.example.com/data")
                .build();
            com.squareup.okhttp.Response response = client.newCall(request).execute();
            // ruleid: java-avoid-native-assert-in-junit
            assert response.code() == 200;
        } catch (Exception e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }
    
    @Test
    public void bad_case_15() {
        // Using native assert in JUnit test with Mockito
        UserService userService = Mockito.mock(UserService.class);
        Mockito.when(userService.getUserById(123)).thenReturn(new User("John", "Doe"));
        
        User user = userService.getUserById(123);
        // ruleid: java-avoid-native-assert-in-junit
        assert user.getFirstName().equals("John");
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    @Test
    public void good_case_1() {
        // Using JUnit assertions in a standard JUnit test
        String response = "Hello, World!";
        // ok: java-avoid-native-assert-in-junit
        assertTrue(response.contains("Hello"));
    }
    
    @JupiterTest
    public void good_case_2() {
        // Using JUnit Jupiter assertions with Spring RestTemplate
        org.springframework.web.client.RestTemplate restTemplate = new org.springframework.web.client.RestTemplate();
        String response = restTemplate.getForObject("https://api.example.com/data", String.class);
        // ok: java-avoid-native-assert-in-junit
        assertNotNull(response);
    }
    
    @Test
    public void good_case_3() {
        // Using JUnit assertions with Apache HttpClient
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet request = new HttpGet("https://api.example.com/users");
            org.apache.http.HttpResponse response = httpClient.execute(request);
            String responseBody = EntityUtils.toString(response.getEntity());
            // ok: java-avoid-native-assert-in-junit
            assertTrue(responseBody.contains("user_id"));
        } catch (Exception e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }
    
    @TestNGTest
    public void good_case_4() {
        // Using TestNG assertions with OkHttp
        try {
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                .url("https://api.example.com/products")
                .build();
            okhttp3.Response response = client.newCall(request).execute();
            String responseBody = response.body().string();
            // ok: java-avoid-native-assert-in-junit
            org.testng.Assert.assertTrue(response.isSuccessful());
        } catch (Exception e) {
            org.testng.Assert.fail("Exception occurred: " + e.getMessage());
        }
    }
    
    @Test
    public void good_case_5() {
        // Using JUnit assertions with Java's HttpURLConnection
        try {
            URL url = new URL("https://api.example.com/status");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            int responseCode = connection.getResponseCode();
            // ok: java-avoid-native-assert-in-junit
            assertEquals(200, responseCode);
        } catch (Exception e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }
    
    @Test
    public void good_case_6() {
        // Using JUnit assertions with Retrofit
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build();
        ApiService service = retrofit.create(ApiService.class);
        try {
            retrofit2.Response<User> response = service.getUser(123).execute();
            // ok: java-avoid-native-assert-in-junit
            assertNotNull(response.body());
        } catch (Exception e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }
    
    @Test
    public void good_case_7() {
        // Using JUnit assertions with AWS SDK
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        boolean exists = s3Client.doesBucketExistV2("my-bucket");
        // ok: java-avoid-native-assert-in-junit
        assertTrue(exists);
    }
    
    @Test
    public void good_case_8() {
        // Using JUnit assertions with Google HTTP Client
        try {
            HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
            HttpRequest request = requestFactory.buildGetRequest(new GenericUrl("https://api.example.com/data"));
            com.google.api.client.http.HttpResponse response = request.execute();
            // ok: java-avoid-native-assert-in-junit
            assertEquals(200, response.getStatusCode());
        } catch (Exception e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }
    
    @Test
    public void good_case_9() {
        // Using JUnit assertions with JSoup
        try {
            Document doc = Jsoup.connect("https://example.com").get();
            String title = doc.title();
            // ok: java-avoid-native-assert-in-junit
            assertTrue(title.contains("Example"));
        } catch (Exception e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }
    
    @Test
    public void good_case_10() {
        // Using JUnit assertions with Selenium
        WebDriver driver = new ChromeDriver();
        driver.get("https://example.com");
        String pageTitle = driver.getTitle();
        // ok: java-avoid-native-assert-in-junit
        assertEquals("Example Domain", pageTitle);
        driver.quit();
    }
    
    @Test
    public void good_case_11() {
        // Using JUnit assertions with Vert.x WebClient
        Vertx vertx = Vertx.vertx();
        WebClient client = WebClient.create(vertx);
        
        client.get(80, "example.com", "/")
            .send(ar -> {
                if (ar.succeeded()) {
                    HttpResponse<Buffer> response = ar.result();
                    // ok: java-avoid-native-assert-in-junit
                    assertEquals(200, response.statusCode());
                } else {
                    fail("Request failed");
                }
            });
    }
    
    @Test
    public void good_case_12() {
        // Using JUnit assertions with Spring MockMvc
        MockMvc mockMvc;  // Assume this is initialized in setup
        try {
            String result = mockMvc.perform(MockMvcRequestBuilders.get("/api/users"))
                .andReturn()
                .getResponse()
                .getContentAsString();
            // ok: java-avoid-native-assert-in-junit
            assertTrue(result.contains("userId"));
        } catch (Exception e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }
    
    @Test
    public void good_case_13() {
        // Using JUnit assertions with RestAssured
        Response response = RestAssured.get("https://api.example.com/users");
        String responseBody = response.getBody().asString();
        // ok: java-avoid-native-assert-in-junit
        assertEquals(200, response.getStatusCode());
    }
    
    @Test
    public void good_case_14() {
        // Using JUnit assertions with Square's OkHttp
        try {
            com.squareup.okhttp.OkHttpClient client = new com.squareup.okhttp.OkHttpClient();
            com.squareup.okhttp.Request request = new com.squareup.okhttp.Request.Builder()
                .url("https://api.example.com/data")
                .build();
            com.squareup.okhttp.Response response = client.newCall(request).execute();
            // ok: java-avoid-native-assert-in-junit
            assertEquals(200, response.code());
        } catch (Exception e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }
    
    @Test
    public void good_case_15() {
        // Using JUnit assertions with Mockito
        UserService userService = Mockito.mock(UserService.class);
        Mockito.when(userService.getUserById(123)).thenReturn(new User("John", "Doe"));
        
        User user = userService.getUserById(123);
        // ok: java-avoid-native-assert-in-junit
        assertEquals("John", user.getFirstName());
    }
    
    // Helper classes for examples
    private interface ApiService {
        retrofit2.Call<User> getUser(int id);
    }
    
    private static class User {
        private String firstName;
        private String lastName;
        
        public User(String firstName, String lastName) {
            this.firstName = firstName;
            this.lastName = lastName;
        }
        
        public String getFirstName() {
            return firstName;
        }
        
        public String getLastName() {
            return lastName;
        }
    }
    
    private interface UserService {
        User getUserById(int id);
    }
}
// {/fact}