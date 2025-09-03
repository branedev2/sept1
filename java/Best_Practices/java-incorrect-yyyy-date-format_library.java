import java.text.SimpleDateFormat;
import java.util.Date;
import java.time.format.DateTimeFormatter;
import java.time.LocalDateTime;
import java.util.Calendar;
import org.joda.time.format.DateTimeFormat;
import org.apache.commons.lang3.time.FastDateFormat;
import org.springframework.format.datetime.DateFormatter;
import com.google.common.base.Stopwatch;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.quartz.CronScheduleBuilder;
import org.quartz.JobBuilder;
import org.quartz.TriggerBuilder;
import java.text.DateFormat;
import java.sql.Timestamp;
import java.text.ParseException;
import org.apache.commons.lang3.time.DateFormatUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import java.time.ZonedDateTime;
import java.time.format.FormatStyle;
import java.util.Locale;

// Security Issue: Incorrect Usage of 'YYYY' in Java Date Formatting

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    String datePattern = request.getParameter("dateFormat");
    if (datePattern == null) {
        // ruleid: java-incorrect-yyyy-date-format
        SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/YYYY");
        System.out.println("Current date: " + sdf.format(new Date()));
    }
}

public void bad_case_2(@RequestParam String dateString) {
    try {
        // ruleid: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd-MM-YYYY");
        LocalDateTime dateTime = LocalDateTime.parse(dateString, formatter);
        System.out.println("Parsed date: " + dateTime);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@Path("/jaxrs")
public void bad_case_3(@QueryParam("format") String format) {
    // ruleid: java-incorrect-yyyy-date-format
    org.joda.time.format.DateTimeFormatter formatter = DateTimeFormat.forPattern("YYYY-MM-dd");
    String formattedDate = formatter.print(org.joda.time.DateTime.now());
    System.out.println("Joda Time formatted date: " + formattedDate);
}

public void bad_case_4(HttpServletRequest request) {
    String logFormat = request.getHeader("Log-Format");
    Logger logger = LogManager.getLogger(getClass());
    // ruleid: java-incorrect-yyyy-date-format
    FastDateFormat fastFormat = FastDateFormat.getInstance("YYYY_MM_dd");
    logger.info("Log entry timestamp: {}", fastFormat.format(new Date()));
}

@GetMapping("/spring-format")
public void bad_case_5(HttpServletRequest request) {
    // ruleid: java-incorrect-yyyy-date-format
    DateFormatter springFormatter = new DateFormatter("YYYY-MM-dd");
    String formattedDate = springFormatter.print(new Date(), Locale.getDefault());
    System.out.println("Spring formatted date: " + formattedDate);
}

public void bad_case_6(HttpServletRequest request) {
    String timestamp = request.getParameter("timestamp");
    try {
        // ruleid: java-incorrect-yyyy-date-format
        String pattern = "YYYY-MM-dd'T'HH:mm:ss.SSSZ";
        java.text.DateFormat df = new java.text.SimpleDateFormat(pattern);
        Date parsedDate = df.parse(timestamp);
        System.out.println("Parsed timestamp: " + parsedDate);
    } catch (ParseException e) {
        e.printStackTrace();
    }
}

@GetMapping("/quartz-job")
public void bad_case_7() {
    // ruleid: java-incorrect-yyyy-date-format
    String cronExpression = "0 0 0 ? * * YYYY";
    try {
        TriggerBuilder.newTrigger()
            .withSchedule(CronScheduleBuilder.cronSchedule(cronExpression))
            .build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8(HttpServletRequest request) {
    // ruleid: java-incorrect-yyyy-date-format
    String dateFormatPattern = "YYYY-MM-dd HH:mm:ss";
    DateFormat dateFormat = new SimpleDateFormat(dateFormatPattern);
    Timestamp timestamp = new Timestamp(System.currentTimeMillis());
    System.out.println("SQL Timestamp formatted: " + dateFormat.format(timestamp));
}

public void bad_case_9(HttpServletRequest request) {
    // ruleid: java-incorrect-yyyy-date-format
    String formattedDate = DateFormatUtils.format(new Date(), "YYYY-MM-dd");
    System.out.println("Apache Commons formatted date: " + formattedDate);
}

@GetMapping("/jackson-date")
public ResponseEntity<String> bad_case_10() {
    ObjectMapper mapper = new ObjectMapper();
    mapper.registerModule(new JavaTimeModule());
    mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    
    try {
        // ruleid: java-incorrect-yyyy-date-format
        DateFormat df = new SimpleDateFormat("YYYY-MM-dd");
        mapper.setDateFormat(df);
        return new ResponseEntity<>(mapper.writeValueAsString(new Date()), HttpStatus.OK);
    } catch (Exception e) {
        return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
    }
}

public void bad_case_11(HttpServletRequest request) {
    // ruleid: java-incorrect-yyyy-date-format
    java.text.DateFormat customFormat = java.text.DateFormat.getDateInstance();
    if (customFormat instanceof SimpleDateFormat) {
        ((SimpleDateFormat) customFormat).applyPattern("YYYY-MM-dd");
    }
    System.out.println("Custom formatted date: " + customFormat.format(new Date()));
}

public void bad_case_12(@RequestParam String inputDate) {
    Calendar calendar = Calendar.getInstance();
    // ruleid: java-incorrect-yyyy-date-format
    SimpleDateFormat sdf = new SimpleDateFormat("YYYY-ww"); // Week of year with year
    try {
        Date date = sdf.parse(inputDate);
        calendar.setTime(date);
        System.out.println("Week number: " + calendar.get(Calendar.WEEK_OF_YEAR));
    } catch (ParseException e) {
        e.printStackTrace();
    }
}

@GetMapping("/zoneddatetime")
public void bad_case_13() {
    ZonedDateTime now = ZonedDateTime.now();
    // ruleid: java-incorrect-yyyy-date-format
    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("YYYY-MM-dd HH:mm:ss z");
    String formatted = now.format(formatter);
    System.out.println("ZonedDateTime formatted: " + formatted);
}

public void bad_case_14(HttpServletRequest request) {
    String pattern = request.getParameter("pattern");
    if (pattern == null) {
        pattern = "YYYY-MM-dd";
    }
    // ruleid: java-incorrect-yyyy-date-format
    DateTimeFormatter formatter = DateTimeFormatter.ofPattern(pattern);
    System.out.println(LocalDateTime.now().format(formatter));
}

@GetMapping("/log-entry")
public void bad_case_15() {
    Logger logger = LogManager.getLogger(getClass());
    Stopwatch stopwatch = Stopwatch.createStarted();
    // ruleid: java-incorrect-yyyy-date-format
    SimpleDateFormat logDateFormat = new SimpleDateFormat("YYYY_MM_dd_HH_mm_ss");
    logger.info("Operation started at {}", logDateFormat.format(new Date()));
    // Do some operation
    stopwatch.stop();
    logger.info("Operation completed in {}", stopwatch);
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    String datePattern = request.getParameter("dateFormat");
    if (datePattern == null) {
        // ok: java-incorrect-yyyy-date-format
        SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy");
        System.out.println("Current date: " + sdf.format(new Date()));
    }
}

public void good_case_2(@RequestParam String dateString) {
    try {
        // ok: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd-MM-yyyy");
        LocalDateTime dateTime = LocalDateTime.parse(dateString, formatter);
        System.out.println("Parsed date: " + dateTime);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@Path("/jaxrs")
public void good_case_3(@QueryParam("format") String format) {
    // ok: java-incorrect-yyyy-date-format
    org.joda.time.format.DateTimeFormatter formatter = DateTimeFormat.forPattern("yyyy-MM-dd");
    String formattedDate = formatter.print(org.joda.time.DateTime.now());
    System.out.println("Joda Time formatted date: " + formattedDate);
}

public void good_case_4(HttpServletRequest request) {
    String logFormat = request.getHeader("Log-Format");
    Logger logger = LogManager.getLogger(getClass());
    // ok: java-incorrect-yyyy-date-format
    FastDateFormat fastFormat = FastDateFormat.getInstance("yyyy_MM_dd");
    logger.info("Log entry timestamp: {}", fastFormat.format(new Date()));
}

@GetMapping("/spring-format")
public void good_case_5(HttpServletRequest request) {
    // ok: java-incorrect-yyyy-date-format
    DateFormatter springFormatter = new DateFormatter("yyyy-MM-dd");
    String formattedDate = springFormatter.print(new Date(), Locale.getDefault());
    System.out.println("Spring formatted date: " + formattedDate);
}

public void good_case_6(HttpServletRequest request) {
    String timestamp = request.getParameter("timestamp");
    try {
        // ok: java-incorrect-yyyy-date-format
        String pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSZ";
        java.text.DateFormat df = new java.text.SimpleDateFormat(pattern);
        Date parsedDate = df.parse(timestamp);
        System.out.println("Parsed timestamp: " + parsedDate);
    } catch (ParseException e) {
        e.printStackTrace();
    }
}

@GetMapping("/quartz-job")
public void good_case_7() {
    // ok: java-incorrect-yyyy-date-format
    String cronExpression = "0 0 0 ? * * *"; // Proper cron expression without YYYY
    try {
        TriggerBuilder.newTrigger()
            .withSchedule(CronScheduleBuilder.cronSchedule(cronExpression))
            .build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8(HttpServletRequest request) {
    // ok: java-incorrect-yyyy-date-format
    String dateFormatPattern = "yyyy-MM-dd HH:mm:ss";
    DateFormat dateFormat = new SimpleDateFormat(dateFormatPattern);
    Timestamp timestamp = new Timestamp(System.currentTimeMillis());
    System.out.println("SQL Timestamp formatted: " + dateFormat.format(timestamp));
}

public void good_case_9(HttpServletRequest request) {
    // ok: java-incorrect-yyyy-date-format
    String formattedDate = DateFormatUtils.format(new Date(), "yyyy-MM-dd");
    System.out.println("Apache Commons formatted date: " + formattedDate);
}

@GetMapping("/jackson-date")
public ResponseEntity<String> good_case_10() {
    ObjectMapper mapper = new ObjectMapper();
    mapper.registerModule(new JavaTimeModule());
    mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    
    try {
        // ok: java-incorrect-yyyy-date-format
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd");
        mapper.setDateFormat(df);
        return new ResponseEntity<>(mapper.writeValueAsString(new Date()), HttpStatus.OK);
    } catch (Exception e) {
        return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
    }
}

public void good_case_11(HttpServletRequest request) {
    // ok: java-incorrect-yyyy-date-format
    java.text.DateFormat customFormat = java.text.DateFormat.getDateInstance();
    if (customFormat instanceof SimpleDateFormat) {
        ((SimpleDateFormat) customFormat).applyPattern("yyyy-MM-dd");
    }
    System.out.println("Custom formatted date: " + customFormat.format(new Date()));
}

public void good_case_12(@RequestParam String inputDate) {
    Calendar calendar = Calendar.getInstance();
    // ok: java-incorrect-yyyy-date-format
    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-ww"); // Week of year with year
    try {
        Date date = sdf.parse(inputDate);
        calendar.setTime(date);
        System.out.println("Week number: " + calendar.get(Calendar.WEEK_OF_YEAR));
    } catch (ParseException e) {
        e.printStackTrace();
    }
}

@GetMapping("/zoneddatetime")
public void good_case_13() {
    ZonedDateTime now = ZonedDateTime.now();
    // ok: java-incorrect-yyyy-date-format
    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z");
    String formatted = now.format(formatter);
    System.out.println("ZonedDateTime formatted: " + formatted);
}

public void good_case_14(HttpServletRequest request) {
    String pattern = request.getParameter("pattern");
    if (pattern == null || pattern.contains("YYYY")) {
        pattern = "yyyy-MM-dd"; // Safe default or correction
    }
    // ok: java-incorrect-yyyy-date-format
    DateTimeFormatter formatter = DateTimeFormatter.ofPattern(pattern);
    System.out.println(LocalDateTime.now().format(formatter));
}

@GetMapping("/log-entry")
public void good_case_15() {
    Logger logger = LogManager.getLogger(getClass());
    Stopwatch stopwatch = Stopwatch.createStarted();
    // ok: java-incorrect-yyyy-date-format
    SimpleDateFormat logDateFormat = new SimpleDateFormat("yyyy_MM_dd_HH_mm_ss");
    logger.info("Operation started at {}", logDateFormat.format(new Date()));
    // Do some operation
    stopwatch.stop();
    logger.info("Operation completed in {}", stopwatch);
}