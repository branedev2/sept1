import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Calendar;
import java.util.Locale;
import java.time.format.DateTimeFormatter;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.text.DateFormat;

public class DateFormatExamples {

    // True Positive Examples (Vulnerable Code)
    
// {fact rule=incorrect-functionality-implementation@v1.0 defects=1}
    public void bad_case_1() {
        // Using YYYY instead of yyyy in SimpleDateFormat
        // ruleid: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("YYYY-MM-dd");
        String formattedDate = dateFormat.format(new Date());
        System.out.println("Formatted date: " + formattedDate);
    }
    
    public void bad_case_2() {
        // Using YYYY in a more complex pattern with time
        // ruleid: java-incorrect-yyyy-date-format
        SimpleDateFormat dateTimeFormat = new SimpleDateFormat("YYYY-MM-dd HH:mm:ss");
        String formattedDateTime = dateTimeFormat.format(new Date());
        System.out.println("Formatted date and time: " + formattedDateTime);
    }
    
    public void bad_case_3() {
        // Using YYYY with locale information
        // ruleid: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("YYYY/MM/dd", Locale.US);
        String formattedDate = dateFormat.format(Calendar.getInstance().getTime());
        System.out.println("US formatted date: " + formattedDate);
    }
    
    public void bad_case_4() {
        // Using YYYY in DateTimeFormatter
        // ruleid: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("YYYY-MM-dd");
        String formattedDate = LocalDate.now().format(formatter);
        System.out.println("Formatted with DateTimeFormatter: " + formattedDate);
    }
    
    public void bad_case_5() {
        // Using YYYY with different separators
        // ruleid: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("YYYY.MM.dd");
        String formattedDate = dateFormat.format(new Date());
        System.out.println("Date with dots: " + formattedDate);
    }
    
    public void bad_case_6() {
        // Using YYYY in a method that processes dates
        Date currentDate = new Date();
        // ruleid: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("YYYY-MM-dd");
        String processedDate = processDate(currentDate, dateFormat);
        System.out.println("Processed date: " + processedDate);
    }
    
    private String processDate(Date date, SimpleDateFormat formatter) {
        return formatter.format(date);
    }
    
    public void bad_case_7() {
        // Using YYYY in DateTimeFormatter with LocalDateTime
        // ruleid: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("YYYY-MM-dd HH:mm:ss");
        String formattedDateTime = LocalDateTime.now().format(formatter);
        System.out.println("LocalDateTime formatted: " + formattedDateTime);
    }
    
    public void bad_case_8() {
        // Using YYYY in a conditional statement
        boolean useShortFormat = false;
        SimpleDateFormat dateFormat;
        if (useShortFormat) {
            dateFormat = new SimpleDateFormat("MM/dd");
        } else {
            // ruleid: java-incorrect-yyyy-date-format
            dateFormat = new SimpleDateFormat("YYYY/MM/dd");
        }
        String formattedDate = dateFormat.format(new Date());
        System.out.println("Conditional format: " + formattedDate);
    }
    
    public void bad_case_9() {
        // Using YYYY with ZonedDateTime
        // ruleid: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("YYYY-MM-dd'T'HH:mm:ssZ");
        String formattedDate = ZonedDateTime.now().format(formatter);
        System.out.println("ZonedDateTime formatted: " + formattedDate);
    }
    
    public void bad_case_10() {
        // Using YYYY in an array of date formats
        SimpleDateFormat[] formats = new SimpleDateFormat[3];
        formats[0] = new SimpleDateFormat("MM/dd");
        // ruleid: java-incorrect-yyyy-date-format
        formats[1] = new SimpleDateFormat("YYYY-MM-dd");
        formats[2] = new SimpleDateFormat("dd.MM");
        
        String formattedDate = formats[1].format(new Date());
        System.out.println("Array format: " + formattedDate);
    }
    
    public void bad_case_11() {
        // Using YYYY in a format with text month
        // ruleid: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("YYYY, MMMM dd");
        String formattedDate = dateFormat.format(new Date());
        System.out.println("Date with text month: " + formattedDate);
    }
    
    public void bad_case_12() {
        // Using YYYY in a dynamic format string
        String yearPattern = "YYYY";
        String monthDayPattern = "-MM-dd";
        // ruleid: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat(yearPattern + monthDayPattern);
        String formattedDate = dateFormat.format(new Date());
        System.out.println("Dynamic format: " + formattedDate);
    }
    
    public void bad_case_13() {
        // Using YYYY in a thread-local SimpleDateFormat
        ThreadLocal<SimpleDateFormat> dateFormatThreadLocal = new ThreadLocal<SimpleDateFormat>() {
            @Override
            protected SimpleDateFormat initialValue() {
                // ruleid: java-incorrect-yyyy-date-format
                return new SimpleDateFormat("YYYY-MM-dd");
            }
        };
        String formattedDate = dateFormatThreadLocal.get().format(new Date());
        System.out.println("Thread-local format: " + formattedDate);
    }
    
    public void bad_case_14() {
        // Using YYYY with day of year
        // ruleid: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("YYYY-DDD");
        String formattedDate = dateFormat.format(new Date());
        System.out.println("Day of year format: " + formattedDate);
    }
    
    public void bad_case_15() {
        // Using YYYY with week of year
        // ruleid: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("YYYY-'W'ww-u");
        String formattedDate = dateFormat.format(new Date());
        System.out.println("ISO week date format: " + formattedDate);
    }
    
    // True Negative Examples (Safe Code)
    
    public void good_case_1() {
        // Using yyyy instead of YYYY in SimpleDateFormat
        // ok: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        String formattedDate = dateFormat.format(new Date());
        System.out.println("Formatted date: " + formattedDate);
    }
    
    public void good_case_2() {
        // Using yyyy in a more complex pattern with time
        // ok: java-incorrect-yyyy-date-format
        SimpleDateFormat dateTimeFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String formattedDateTime = dateTimeFormat.format(new Date());
        System.out.println("Formatted date and time: " + formattedDateTime);
    }
    
    public void good_case_3() {
        // Using yyyy with locale information
        // ok: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd", Locale.US);
        String formattedDate = dateFormat.format(Calendar.getInstance().getTime());
        System.out.println("US formatted date: " + formattedDate);
    }
    
    public void good_case_4() {
        // Using yyyy in DateTimeFormatter
        // ok: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        String formattedDate = LocalDate.now().format(formatter);
        System.out.println("Formatted with DateTimeFormatter: " + formattedDate);
    }
    
    public void good_case_5() {
        // Using yyyy with different separators
        // ok: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy.MM.dd");
        String formattedDate = dateFormat.format(new Date());
        System.out.println("Date with dots: " + formattedDate);
    }
    
    public void good_case_6() {
        // Using yyyy in a method that processes dates
        Date currentDate = new Date();
        // ok: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        String processedDate = processDate(currentDate, dateFormat);
        System.out.println("Processed date: " + processedDate);
    }
    
    public void good_case_7() {
        // Using yyyy in DateTimeFormatter with LocalDateTime
        // ok: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        String formattedDateTime = LocalDateTime.now().format(formatter);
        System.out.println("LocalDateTime formatted: " + formattedDateTime);
    }
    
    public void good_case_8() {
        // Using yyyy in a conditional statement
        boolean useShortFormat = false;
        SimpleDateFormat dateFormat;
        if (useShortFormat) {
            dateFormat = new SimpleDateFormat("MM/dd");
        } else {
            // ok: java-incorrect-yyyy-date-format
            dateFormat = new SimpleDateFormat("yyyy/MM/dd");
        }
        String formattedDate = dateFormat.format(new Date());
        System.out.println("Conditional format: " + formattedDate);
    }
    
    public void good_case_9() {
        // Using yyyy with ZonedDateTime
        // ok: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssZ");
        String formattedDate = ZonedDateTime.now().format(formatter);
        System.out.println("ZonedDateTime formatted: " + formattedDate);
    }
    
    public void good_case_10() {
        // Using yyyy in an array of date formats
        SimpleDateFormat[] formats = new SimpleDateFormat[3];
        formats[0] = new SimpleDateFormat("MM/dd");
        // ok: java-incorrect-yyyy-date-format
        formats[1] = new SimpleDateFormat("yyyy-MM-dd");
        formats[2] = new SimpleDateFormat("dd.MM");
        
        String formattedDate = formats[1].format(new Date());
        System.out.println("Array format: " + formattedDate);
    }
    
    public void good_case_11() {
        // Using a format without year pattern (no issue)
        // ok: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("MMMM dd");
        String formattedDate = dateFormat.format(new Date());
        System.out.println("Date without year: " + formattedDate);
    }
    
    public void good_case_12() {
        // Using predefined date format constants
        // ok: java-incorrect-yyyy-date-format
        DateFormat dateFormat = DateFormat.getDateInstance(DateFormat.SHORT);
        String formattedDate = dateFormat.format(new Date());
        System.out.println("Predefined format: " + formattedDate);
    }
    
    public void good_case_13() {
        // Using yyyy in a dynamic format string
        String yearPattern = "yyyy";
        String monthDayPattern = "-MM-dd";
        // ok: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat(yearPattern + monthDayPattern);
        String formattedDate = dateFormat.format(new Date());
        System.out.println("Dynamic format: " + formattedDate);
    }
    
    public void good_case_14() {
        // Using yyyy with day of year
        // ok: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-DDD");
        String formattedDate = dateFormat.format(new Date());
        System.out.println("Day of year format: " + formattedDate);
    }
    
    public void good_case_15() {
        // Using yyyy with week of year
        // ok: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-'W'ww-u");
        String formattedDate = dateFormat.format(new Date());
        System.out.println("ISO week date format: " + formattedDate);
    }
}
// {/fact}