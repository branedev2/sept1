import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.*;
import java.util.function.*;
import java.util.stream.*;
import java.time.*;
import java.time.format.*;

// Backport imports (for bad examples)
import edu.emory.mathcs.backport.java.util.*;
import edu.emory.mathcs.backport.java.util.concurrent.*;
import edu.emory.mathcs.backport.java.util.concurrent.locks.*;
import edu.emory.mathcs.backport.java.util.function.*;

public class JavaNativeApiExamples {

    // BAD EXAMPLES - Using backported classes instead of native Java APIs

// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1() {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.ConcurrentHashMap<String, Integer> map = 
            new edu.emory.mathcs.backport.java.util.concurrent.ConcurrentHashMap<>();
        
        map.put("key1", 100);
        map.put("key2", 200);
        
        System.out.println("Value: " + map.get("key1"));
    }
    
    public void bad_case_2() {
        List<String> items = Arrays.asList("apple", "banana", "orange");
        
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.Collections.shuffle(items);
        
        for (String item : items) {
            System.out.println(item);
        }
    }
    
    public void bad_case_3() {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.locks.ReentrantLock lock = 
            new edu.emory.mathcs.backport.java.util.concurrent.locks.ReentrantLock();
        
        try {
            lock.lock();
            // Critical section
            System.out.println("Executing critical section");
        } finally {
            lock.unlock();
        }
    }
    
    public void bad_case_4() {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.ExecutorService executor = 
            edu.emory.mathcs.backport.java.util.concurrent.Executors.newFixedThreadPool(5);
        
        executor.submit(() -> {
            System.out.println("Task executed");
        });
        
        executor.shutdown();
    }
    
    public void bad_case_5() {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.PriorityQueue<Integer> queue = 
            new edu.emory.mathcs.backport.java.util.PriorityQueue<>();
        
        queue.add(10);
        queue.add(5);
        queue.add(15);
        
        while (!queue.isEmpty()) {
            System.out.println(queue.poll());
        }
    }
    
    public void bad_case_6() {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.atomic.AtomicInteger counter = 
            new edu.emory.mathcs.backport.java.util.concurrent.atomic.AtomicInteger(0);
        
        for (int i = 0; i < 10; i++) {
            counter.incrementAndGet();
        }
        
        System.out.println("Counter: " + counter.get());
    }
    
    public void bad_case_7() {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.LinkedHashMap<String, Integer> map = 
            new edu.emory.mathcs.backport.java.util.LinkedHashMap<>();
        
        map.put("one", 1);
        map.put("two", 2);
        map.put("three", 3);
        
        for (Map.Entry<String, Integer> entry : map.entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue());
        }
    }
    
    public void bad_case_8() {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.CountDownLatch latch = 
            new edu.emory.mathcs.backport.java.util.concurrent.CountDownLatch(3);
        
        for (int i = 0; i < 3; i++) {
            new Thread(() -> {
                try {
                    Thread.sleep(1000);
                    latch.countDown();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }).start();
        }
        
        try {
            latch.await();
            System.out.println("All tasks completed");
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_9() {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.TreeSet<String> set = 
            new edu.emory.mathcs.backport.java.util.TreeSet<>();
        
        set.add("banana");
        set.add("apple");
        set.add("orange");
        
        for (String fruit : set) {
            System.out.println(fruit);
        }
    }
    
    public void bad_case_10() {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.CyclicBarrier barrier = 
            new edu.emory.mathcs.backport.java.util.concurrent.CyclicBarrier(3, () -> {
                System.out.println("Barrier action executed");
            });
        
        for (int i = 0; i < 3; i++) {
            new Thread(() -> {
                try {
                    System.out.println("Thread waiting at barrier");
                    barrier.await();
                    System.out.println("Thread passed barrier");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
        }
    }
    
    public void bad_case_11() {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.Semaphore semaphore = 
            new edu.emory.mathcs.backport.java.util.concurrent.Semaphore(2);
        
        for (int i = 0; i < 5; i++) {
            new Thread(() -> {
                try {
                    semaphore.acquire();
                    System.out.println("Semaphore acquired");
                    Thread.sleep(1000);
                    semaphore.release();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }).start();
        }
    }
    
    public void bad_case_12() {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.ArrayDeque<String> deque = 
            new edu.emory.mathcs.backport.java.util.ArrayDeque<>();
        
        deque.addFirst("first");
        deque.addLast("last");
        
        System.out.println("First: " + deque.getFirst());
        System.out.println("Last: " + deque.getLast());
    }
    
    public void bad_case_13() {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.NavigableMap<Integer, String> map = 
            new edu.emory.mathcs.backport.java.util.TreeMap<>();
        
        map.put(1, "one");
        map.put(2, "two");
        map.put(3, "three");
        
        System.out.println("Floor entry for 2.5: " + map.floorEntry(2));
        System.out.println("Ceiling entry for 2.5: " + map.ceilingEntry(3));
    }
    
    public void bad_case_14() {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.BlockingQueue<String> queue = 
            new edu.emory.mathcs.backport.java.util.concurrent.LinkedBlockingQueue<>();
        
        new Thread(() -> {
            try {
                for (int i = 0; i < 5; i++) {
                    queue.put("Item " + i);
                    Thread.sleep(100);
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }).start();
        
        new Thread(() -> {
            try {
                for (int i = 0; i < 5; i++) {
                    String item = queue.take();
                    System.out.println("Processed: " + item);
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }).start();
    }
    
    public void bad_case_15() {
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.ScheduledExecutorService scheduler = 
            edu.emory.mathcs.backport.java.util.concurrent.Executors.newScheduledThreadPool(1);
        
        scheduler.scheduleAtFixedRate(() -> {
            System.out.println("Task executed at: " + System.currentTimeMillis());
        }, 0, 1000, TimeUnit.MILLISECONDS);
        
        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        
        scheduler.shutdown();
    }
    
    // GOOD EXAMPLES - Using native Java APIs instead of backported classes
    
    public void good_case_1() {
        // ok: java-native-api
        java.util.concurrent.ConcurrentHashMap<String, Integer> map = 
            new java.util.concurrent.ConcurrentHashMap<>();
        
        map.put("key1", 100);
        map.put("key2", 200);
        
        System.out.println("Value: " + map.get("key1"));
    }
    
    public void good_case_2() {
        List<String> items = Arrays.asList("apple", "banana", "orange");
        
        // ok: java-native-api
        java.util.Collections.shuffle(items);
        
        for (String item : items) {
            System.out.println(item);
        }
    }
    
    public void good_case_3() {
        // ok: java-native-api
        java.util.concurrent.locks.ReentrantLock lock = 
            new java.util.concurrent.locks.ReentrantLock();
        
        try {
            lock.lock();
            // Critical section
            System.out.println("Executing critical section");
        } finally {
            lock.unlock();
        }
    }
    
    public void good_case_4() {
        // ok: java-native-api
        java.util.concurrent.ExecutorService executor = 
            java.util.concurrent.Executors.newFixedThreadPool(5);
        
        executor.submit(() -> {
            System.out.println("Task executed");
        });
        
        executor.shutdown();
    }
    
    public void good_case_5() {
        // ok: java-native-api
        java.util.PriorityQueue<Integer> queue = 
            new java.util.PriorityQueue<>();
        
        queue.add(10);
        queue.add(5);
        queue.add(15);
        
        while (!queue.isEmpty()) {
            System.out.println(queue.poll());
        }
    }
    
    public void good_case_6() {
        // ok: java-native-api
        java.util.concurrent.atomic.AtomicInteger counter = 
            new java.util.concurrent.atomic.AtomicInteger(0);
        
        for (int i = 0; i < 10; i++) {
            counter.incrementAndGet();
        }
        
        System.out.println("Counter: " + counter.get());
    }
    
    public void good_case_7() {
        // ok: java-native-api
        java.util.LinkedHashMap<String, Integer> map = 
            new java.util.LinkedHashMap<>();
        
        map.put("one", 1);
        map.put("two", 2);
        map.put("three", 3);
        
        for (Map.Entry<String, Integer> entry : map.entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue());
        }
    }
    
    public void good_case_8() {
        // ok: java-native-api
        java.util.concurrent.CountDownLatch latch = 
            new java.util.concurrent.CountDownLatch(3);
        
        for (int i = 0; i < 3; i++) {
            new Thread(() -> {
                try {
                    Thread.sleep(1000);
                    latch.countDown();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }).start();
        }
        
        try {
            latch.await();
            System.out.println("All tasks completed");
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_9() {
        // ok: java-native-api
        java.util.TreeSet<String> set = 
            new java.util.TreeSet<>();
        
        set.add("banana");
        set.add("apple");
        set.add("orange");
        
        for (String fruit : set) {
            System.out.println(fruit);
        }
    }
    
    public void good_case_10() {
        // ok: java-native-api
        java.util.concurrent.CyclicBarrier barrier = 
            new java.util.concurrent.CyclicBarrier(3, () -> {
                System.out.println("Barrier action executed");
            });
        
        for (int i = 0; i < 3; i++) {
            new Thread(() -> {
                try {
                    System.out.println("Thread waiting at barrier");
                    barrier.await();
                    System.out.println("Thread passed barrier");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
        }
    }
    
    public void good_case_11() {
        // ok: java-native-api
        java.util.concurrent.Semaphore semaphore = 
            new java.util.concurrent.Semaphore(2);
        
        for (int i = 0; i < 5; i++) {
            new Thread(() -> {
                try {
                    semaphore.acquire();
                    System.out.println("Semaphore acquired");
                    Thread.sleep(1000);
                    semaphore.release();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }).start();
        }
    }
    
    public void good_case_12() {
        // ok: java-native-api
        java.util.ArrayDeque<String> deque = 
            new java.util.ArrayDeque<>();
        
        deque.addFirst("first");
        deque.addLast("last");
        
        System.out.println("First: " + deque.getFirst());
        System.out.println("Last: " + deque.getLast());
    }
    
    public void good_case_13() {
        // ok: java-native-api
        java.util.NavigableMap<Integer, String> map = 
            new java.util.TreeMap<>();
        
        map.put(1, "one");
        map.put(2, "two");
        map.put(3, "three");
        
        System.out.println("Floor entry for 2.5: " + map.floorEntry(2));
        System.out.println("Ceiling entry for 2.5: " + map.ceilingEntry(3));
    }
    
    public void good_case_14() {
        // ok: java-native-api
        java.util.concurrent.BlockingQueue<String> queue = 
            new java.util.concurrent.LinkedBlockingQueue<>();
        
        new Thread(() -> {
            try {
                for (int i = 0; i < 5; i++) {
                    queue.put("Item " + i);
                    Thread.sleep(100);
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }).start();
        
        new Thread(() -> {
            try {
                for (int i = 0; i < 5; i++) {
                    String item = queue.take();
                    System.out.println("Processed: " + item);
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }).start();
    }
    
    public void good_case_15() {
        // ok: java-native-api
        java.util.concurrent.ScheduledExecutorService scheduler = 
            java.util.concurrent.Executors.newScheduledThreadPool(1);
        
        scheduler.scheduleAtFixedRate(() -> {
            System.out.println("Task executed at: " + System.currentTimeMillis());
        }, 0, 1000, TimeUnit.MILLISECONDS);
        
        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        
        scheduler.shutdown();
    }
}
// {/fact}