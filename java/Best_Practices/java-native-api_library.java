import java.util.*;
import java.util.concurrent.*;
import java.util.stream.*;
import java.time.*;
import java.time.format.*;
import java.util.regex.*;
import java.nio.file.*;
import java.io.*;
import java.net.*;
import java.util.function.*;
import javax.servlet.http.*;
import javax.servlet.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import org.springframework.http.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;
import org.apache.http.util.*;
import com.google.common.collect.*;
import com.fasterxml.jackson.databind.*;
import org.apache.commons.collections4.*;
import org.apache.commons.lang3.*;
import edu.emory.mathcs.backport.java.util.*;
import edu.emory.mathcs.backport.java.util.concurrent.*;
import edu.emory.mathcs.backport.java.util.Arrays;

// Security Issue: Using backported libraries (edu.emory.mathcs.backport) instead of native Java APIs

// True Positive Examples (Vulnerable/Insecure Code)

public class BackportUsageExamples {

    // True Positive Examples (Vulnerable/Insecure Code)
    
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        String input = request.getParameter("data");
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.ConcurrentHashMap<String, String> map = 
            new edu.emory.mathcs.backport.java.util.concurrent.ConcurrentHashMap<>();
        map.put("userInput", input);
        System.out.println("Stored input: " + map.get("userInput"));
    }
    
    public void bad_case_2(HttpServletRequest request) {
        String[] inputs = request.getParameterValues("items");
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.Arrays.sort(inputs);
        for (String item : inputs) {
            System.out.println("Sorted item: " + item);
        }
    }
    
    @Controller
    public void bad_case_3(@RequestParam("timeout") long timeout) {
        try {
            // ruleid: java-native-api
            edu.emory.mathcs.backport.java.util.concurrent.TimeUnit.MILLISECONDS.sleep(timeout);
            System.out.println("Slept for " + timeout + " milliseconds");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    public void bad_case_4(HttpServletRequest request) {
        String input = request.getParameter("data");
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.LinkedList<String> list = 
            new edu.emory.mathcs.backport.java.util.LinkedList<>();
        list.add(input);
        System.out.println("First element: " + list.getFirst());
    }
    
    public void bad_case_5(HttpServletRequest request) {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.PriorityQueue<String> queue = 
            new edu.emory.mathcs.backport.java.util.PriorityQueue<>();
        queue.add(request.getParameter("priority1"));
        queue.add(request.getParameter("priority2"));
        System.out.println("Highest priority: " + queue.poll());
    }
    
    public void bad_case_6(HttpServletRequest request) {
        String[] values = request.getParameterValues("values");
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.Collections.shuffle(
            edu.emory.mathcs.backport.java.util.Arrays.asList(values));
        System.out.println("Shuffled values: " + Arrays.toString(values));
    }
    
    public void bad_case_7(HttpServletRequest request) {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.locks.ReentrantLock lock = 
            new edu.emory.mathcs.backport.java.util.concurrent.locks.ReentrantLock();
        lock.lock();
        try {
            System.out.println("Processing: " + request.getParameter("data"));
        } finally {
            lock.unlock();
        }
    }
    
    public void bad_case_8(HttpServletRequest request) {
        String input = request.getParameter("data");
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.TreeMap<String, String> map = 
            new edu.emory.mathcs.backport.java.util.TreeMap<>();
        map.put("userInput", input);
        System.out.println("Stored input: " + map.get("userInput"));
    }
    
    public void bad_case_9(HttpServletRequest request) {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.atomic.AtomicInteger counter = 
            new edu.emory.mathcs.backport.java.util.concurrent.atomic.AtomicInteger(0);
        counter.incrementAndGet();
        System.out.println("Request count: " + counter.get() + " for IP: " + request.getRemoteAddr());
    }
    
    public void bad_case_10(HttpServletRequest request) {
        String[] inputs = request.getParameterValues("items");
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.CopyOnWriteArrayList<String> list = 
            new edu.emory.mathcs.backport.java.util.concurrent.CopyOnWriteArrayList<>(inputs);
        System.out.println("Thread-safe list size: " + list.size());
    }
    
    public void bad_case_11(HttpServletRequest request) {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.Executors.newFixedThreadPool(10)
            .submit(() -> System.out.println("Processing request from: " + request.getRemoteAddr()));
    }
    
    public void bad_case_12(HttpServletRequest request) {
        String input = request.getParameter("data");
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.ConcurrentSkipListMap<String, String> map = 
            new edu.emory.mathcs.backport.java.util.concurrent.ConcurrentSkipListMap<>();
        map.put("userInput", input);
        System.out.println("Stored input: " + map.get("userInput"));
    }
    
    public void bad_case_13(HttpServletRequest request) {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.Semaphore semaphore = 
            new edu.emory.mathcs.backport.java.util.concurrent.Semaphore(5);
        try {
            semaphore.acquire();
            System.out.println("Processing: " + request.getParameter("data"));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            semaphore.release();
        }
    }
    
    public void bad_case_14(HttpServletRequest request) {
        String input = request.getParameter("data");
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.DelayQueue<
            edu.emory.mathcs.backport.java.util.concurrent.Delayed> queue = 
            new edu.emory.mathcs.backport.java.util.concurrent.DelayQueue<>();
        System.out.println("Created delay queue for: " + input);
    }
    
    public void bad_case_15(HttpServletRequest request) {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.WeakHashMap<String, String> cache = 
            new edu.emory.mathcs.backport.java.util.WeakHashMap<>();
        cache.put(request.getSession().getId(), request.getParameter("data"));
        System.out.println("Cached data: " + cache.get(request.getSession().getId()));
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    public void good_case_1(HttpServletRequest request) {
        String input = request.getParameter("data");
        // ok: java-native-api
        java.util.concurrent.ConcurrentHashMap<String, String> map = 
            new java.util.concurrent.ConcurrentHashMap<>();
        map.put("userInput", input);
        System.out.println("Stored input: " + map.get("userInput"));
    }
    
    public void good_case_2(HttpServletRequest request) {
        String[] inputs = request.getParameterValues("items");
        // ok: java-native-api
        java.util.Arrays.sort(inputs);
        for (String item : inputs) {
            System.out.println("Sorted item: " + item);
        }
    }
    
    @Controller
    public void good_case_3(@RequestParam("timeout") long timeout) {
        try {
            // ok: java-native-api
            java.util.concurrent.TimeUnit.MILLISECONDS.sleep(timeout);
            System.out.println("Slept for " + timeout + " milliseconds");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    public void good_case_4(HttpServletRequest request) {
        String input = request.getParameter("data");
        // ok: java-native-api
        java.util.LinkedList<String> list = new java.util.LinkedList<>();
        list.add(input);
        System.out.println("First element: " + list.getFirst());
    }
    
    public void good_case_5(HttpServletRequest request) {
        // ok: java-native-api
        java.util.PriorityQueue<String> queue = new java.util.PriorityQueue<>();
        queue.add(request.getParameter("priority1"));
        queue.add(request.getParameter("priority2"));
        System.out.println("Highest priority: " + queue.poll());
    }
    
    public void good_case_6(HttpServletRequest request) {
        String[] values = request.getParameterValues("values");
        // ok: java-native-api
        java.util.Collections.shuffle(java.util.Arrays.asList(values));
        System.out.println("Shuffled values: " + Arrays.toString(values));
    }
    
    public void good_case_7(HttpServletRequest request) {
        // ok: java-native-api
        java.util.concurrent.locks.ReentrantLock lock = new java.util.concurrent.locks.ReentrantLock();
        lock.lock();
        try {
            System.out.println("Processing: " + request.getParameter("data"));
        } finally {
            lock.unlock();
        }
    }
    
    public void good_case_8(HttpServletRequest request) {
        String input = request.getParameter("data");
        // ok: java-native-api
        java.util.TreeMap<String, String> map = new java.util.TreeMap<>();
        map.put("userInput", input);
        System.out.println("Stored input: " + map.get("userInput"));
    }
    
    public void good_case_9(HttpServletRequest request) {
        // ok: java-native-api
        java.util.concurrent.atomic.AtomicInteger counter = new java.util.concurrent.atomic.AtomicInteger(0);
        counter.incrementAndGet();
        System.out.println("Request count: " + counter.get() + " for IP: " + request.getRemoteAddr());
    }
    
    public void good_case_10(HttpServletRequest request) {
        String[] inputs = request.getParameterValues("items");
        // ok: java-native-api
        java.util.concurrent.CopyOnWriteArrayList<String> list = 
            new java.util.concurrent.CopyOnWriteArrayList<>(inputs);
        System.out.println("Thread-safe list size: " + list.size());
    }
    
    public void good_case_11(HttpServletRequest request) {
        // ok: java-native-api
        java.util.concurrent.Executors.newFixedThreadPool(10)
            .submit(() -> System.out.println("Processing request from: " + request.getRemoteAddr()));
    }
    
    public void good_case_12(HttpServletRequest request) {
        String input = request.getParameter("data");
        // ok: java-native-api
        java.util.concurrent.ConcurrentSkipListMap<String, String> map = 
            new java.util.concurrent.ConcurrentSkipListMap<>();
        map.put("userInput", input);
        System.out.println("Stored input: " + map.get("userInput"));
    }
    
    public void good_case_13(HttpServletRequest request) {
        // ok: java-native-api
        java.util.concurrent.Semaphore semaphore = new java.util.concurrent.Semaphore(5);
        try {
            semaphore.acquire();
            System.out.println("Processing: " + request.getParameter("data"));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            semaphore.release();
        }
    }
    
    public void good_case_14(HttpServletRequest request) {
        String input = request.getParameter("data");
        // ok: java-native-api
        java.util.concurrent.DelayQueue<java.util.concurrent.Delayed> queue = 
            new java.util.concurrent.DelayQueue<>();
        System.out.println("Created delay queue for: " + input);
    }
    
    public void good_case_15(HttpServletRequest request) {
        // ok: java-native-api
        java.util.WeakHashMap<String, String> cache = new java.util.WeakHashMap<>();
        cache.put(request.getSession().getId(), request.getParameter("data"));
        System.out.println("Cached data: " + cache.get(request.getSession().getId()));
    }
}
// {/fact}