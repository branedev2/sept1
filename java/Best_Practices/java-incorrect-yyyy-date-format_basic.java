import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.logging.Logger;

public class DateFormatExamples {
    private static final Logger logger = Logger.getLogger(DateFormatExamples.class.getName());

    // True Positives (Vulnerable Code)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1() {
        // Using YYYY in SimpleDateFormat which is incorrect for calendar year
        // ruleid: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("YYYY-MM-dd");
        String formattedDate = dateFormat.format(new Date());
        logger.info("Formatted date: " + formattedDate);
    }

    public void bad_case_2() {
        // Using YYYY in DateTimeFormatter with LocalDate
        // ruleid: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("YYYY-MM-dd");
        String formattedDate = LocalDate.now().format(formatter);
        System.out.println("Today's date: " + formattedDate);
    }

    public void bad_case_3() {
        // Using YYYY in a more complex pattern with time
        // ruleid: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("YYYY-MM-dd HH:mm:ss");
        String timestamp = dateFormat.format(Calendar.getInstance().getTime());
        logger.warning("Current timestamp: " + timestamp);
    }

    public void bad_case_4() {
        // Using YYYY with DateTimeFormatter and LocalDateTime
        // ruleid: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("YYYY/MM/dd HH:mm");
        LocalDateTime now = LocalDateTime.now();
        String formatted = now.format(formatter);
        System.out.println(formatted);
    }

    public void bad_case_5() {
        // Using YYYY in a custom date format with slashes
        // ruleid: java-incorrect-yyyy-date-format
        SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/YYYY");
        String date = sdf.format(new Date());
        logger.info("Date in dd/MM/YYYY format: " + date);
    }

    public void bad_case_6() {
        // Using YYYY with locale information
        // ruleid: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("YYYY-MM-dd", Locale.US);
        String formattedDate = dateFormat.format(new Date());
        System.out.println("US formatted date: " + formattedDate);
    }

    public void bad_case_7() {
        // Using YYYY in DateTimeFormatter with ZonedDateTime
        // ruleid: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("YYYY.MM.dd");
        ZonedDateTime now = ZonedDateTime.now();
        String formatted = now.format(formatter);
        logger.info("Zoned date: " + formatted);
    }

    public void bad_case_8() {
        // Using YYYY in a method that creates a formatter dynamically
        String pattern = "YYYY-MM-dd";
        // ruleid: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(pattern);
        String date = LocalDate.now().format(formatter);
        System.out.println("Dynamic pattern date: " + date);
    }

    public void bad_case_9() {
        // Using YYYY in a conditional statement
        boolean useShortFormat = false;
        // ruleid: java-incorrect-yyyy-date-format
        SimpleDateFormat sdf = useShortFormat 
            ? new SimpleDateFormat("YY/MM/dd") 
            : new SimpleDateFormat("YYYY/MM/dd");
        System.out.println(sdf.format(new Date()));
    }

    public void bad_case_10() {
        // Using YYYY with additional text in the pattern
        // ruleid: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("'Date: 'YYYY-MM-dd");
        String formattedDate = LocalDate.now().format(formatter);
        logger.info(formattedDate);
    }

    public void bad_case_11() {
        // Using YYYY in a format with day name
        // ruleid: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("E, YYYY-MM-dd");
        String date = dateFormat.format(new Date());
        System.out.println("Date with day name: " + date);
    }

    public void bad_case_12() {
        // Using YYYY in a method that formats a specific date
        Calendar cal = Calendar.getInstance();
        cal.set(2023, Calendar.DECEMBER, 31);
        // ruleid: java-incorrect-yyyy-date-format
        SimpleDateFormat sdf = new SimpleDateFormat("YYYY-MM-dd");
        String yearEnd = sdf.format(cal.getTime());
        logger.info("Year end date: " + yearEnd);
    }

    public void bad_case_13() {
        // Using YYYY in a format with month name
        // ruleid: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("YYYY, MMMM dd");
        String formattedDate = dateFormat.format(new Date());
        System.out.println(formattedDate);
    }

    public void bad_case_14() {
        // Using YYYY in a format with both date and time, including milliseconds
        // ruleid: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("YYYY-MM-dd'T'HH:mm:ss.SSS");
        String timestamp = LocalDateTime.now().format(formatter);
        logger.info("ISO-like timestamp: " + timestamp);
    }

    public void bad_case_15() {
        // Using YYYY in a method that creates multiple formatters
        // ruleid: java-incorrect-yyyy-date-format
        SimpleDateFormat longFormat = new SimpleDateFormat("YYYY-MM-dd");
        SimpleDateFormat shortFormat = new SimpleDateFormat("MM/dd");
        
        Date now = new Date();
        System.out.println("Long format: " + longFormat.format(now));
        System.out.println("Short format: " + shortFormat.format(now));
    }

    // True Negatives (Safe Code)

    public void good_case_1() {
        // Using yyyy in SimpleDateFormat which is correct for calendar year
        // ok: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        String formattedDate = dateFormat.format(new Date());
        logger.info("Formatted date: " + formattedDate);
    }

    public void good_case_2() {
        // Using yyyy in DateTimeFormatter with LocalDate
        // ok: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        String formattedDate = LocalDate.now().format(formatter);
        System.out.println("Today's date: " + formattedDate);
    }

    public void good_case_3() {
        // Using yyyy in a more complex pattern with time
        // ok: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String timestamp = dateFormat.format(Calendar.getInstance().getTime());
        logger.warning("Current timestamp: " + timestamp);
    }

    public void good_case_4() {
        // Using yyyy with DateTimeFormatter and LocalDateTime
        // ok: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm");
        LocalDateTime now = LocalDateTime.now();
        String formatted = now.format(formatter);
        System.out.println(formatted);
    }

    public void good_case_5() {
        // Using yyyy in a custom date format with slashes
        // ok: java-incorrect-yyyy-date-format
        SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy");
        String date = sdf.format(new Date());
        logger.info("Date in dd/MM/yyyy format: " + date);
    }

    public void good_case_6() {
        // Using predefined ISO date formatter which uses yyyy internally
        // ok: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE;
        String formattedDate = LocalDate.now().format(formatter);
        System.out.println("ISO date: " + formattedDate);
    }

    public void good_case_7() {
        // Using yyyy with locale information
        // ok: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
        String formattedDate = dateFormat.format(new Date());
        System.out.println("US formatted date: " + formattedDate);
    }

    public void good_case_8() {
        // Using yy for two-digit year (different use case, not the same vulnerability)
        // ok: java-incorrect-yyyy-date-format
        SimpleDateFormat shortYearFormat = new SimpleDateFormat("yy-MM-dd");
        String shortYear = shortYearFormat.format(new Date());
        logger.info("Short year format: " + shortYear);
    }

    public void good_case_9() {
        // Using yyyy in DateTimeFormatter with ZonedDateTime
        // ok: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy.MM.dd");
        ZonedDateTime now = ZonedDateTime.now();
        String formatted = now.format(formatter);
        logger.info("Zoned date: " + formatted);
    }

    public void good_case_10() {
        // Using yyyy in a method that creates a formatter dynamically
        String pattern = "yyyy-MM-dd";
        // ok: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(pattern);
        String date = LocalDate.now().format(formatter);
        System.out.println("Dynamic pattern date: " + date);
    }

    public void good_case_11() {
        // Using yyyy in a conditional statement
        boolean useShortFormat = false;
        // ok: java-incorrect-yyyy-date-format
        SimpleDateFormat sdf = useShortFormat 
            ? new SimpleDateFormat("yy/MM/dd") 
            : new SimpleDateFormat("yyyy/MM/dd");
        System.out.println(sdf.format(new Date()));
    }

    public void good_case_12() {
        // Using yyyy with additional text in the pattern
        // ok: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("'Date: 'yyyy-MM-dd");
        String formattedDate = LocalDate.now().format(formatter);
        logger.info(formattedDate);
    }

    public void good_case_13() {
        // Using yyyy in a format with day name
        // ok: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("E, yyyy-MM-dd");
        String date = dateFormat.format(new Date());
        System.out.println("Date with day name: " + date);
    }

    public void good_case_14() {
        // Using yyyy in a format with month name
        // ok: java-incorrect-yyyy-date-format
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy, MMMM dd");
        String formattedDate = dateFormat.format(new Date());
        System.out.println(formattedDate);
    }

    public void good_case_15() {
        // Using yyyy in a format with both date and time, including milliseconds
        // ok: java-incorrect-yyyy-date-format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS");
        String timestamp = LocalDateTime.now().format(formatter);
        logger.info("ISO-like timestamp: " + timestamp);
    }
}
// {/fact}