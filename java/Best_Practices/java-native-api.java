import java.util.concurrent.*;
import java.util.concurrent.locks.*;
import java.util.*;
import java.time.*;
import java.time.format.*;
import java.util.stream.*;
import edu.emory.mathcs.backport.java.util.concurrent.*;
import edu.emory.mathcs.backport.java.util.*;
import edu.emory.mathcs.backport.java.util.concurrent.locks.*;

public class BackportUsageExamples {

    // True Positive Examples (vulnerable/insecure code that MUST be detected)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1() {
        // Using backported concurrent HashMap instead of native Java implementation
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.ConcurrentHashMap<String, String> map = 
            new edu.emory.mathcs.backport.java.util.concurrent.ConcurrentHashMap<>();
        map.put("key", "value");
        System.out.println("Value: " + map.get("key"));
    }

    public void bad_case_2() {
        // Using backported ArrayBlockingQueue instead of native Java implementation
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.ArrayBlockingQueue<String> queue = 
            new edu.emory.mathcs.backport.java.util.concurrent.ArrayBlockingQueue<>(10);
        queue.add("item");
        System.out.println("Queue size: " + queue.size());
    }

    public void bad_case_3() {
        // Using backported ReentrantLock instead of native Java implementation
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.locks.ReentrantLock lock = 
            new edu.emory.mathcs.backport.java.util.concurrent.locks.ReentrantLock();
        lock.lock();
        try {
            System.out.println("Critical section");
        } finally {
            lock.unlock();
        }
    }

    public void bad_case_4() {
        // Using backported Callable interface instead of native Java implementation
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.Callable<String> callable = 
            new edu.emory.mathcs.backport.java.util.concurrent.Callable<String>() {
                public String call() throws Exception {
                    return "Result";
                }
            };
        System.out.println("Created callable");
    }

    public void bad_case_5() {
        // Using backported ThreadPoolExecutor instead of native Java implementation
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.ThreadPoolExecutor executor = 
            new edu.emory.mathcs.backport.java.util.concurrent.ThreadPoolExecutor(
                5, 10, 60, edu.emory.mathcs.backport.java.util.concurrent.TimeUnit.SECONDS,
                new edu.emory.mathcs.backport.java.util.concurrent.LinkedBlockingQueue<>());
        executor.shutdown();
    }

    public void bad_case_6() {
        // Using backported PriorityQueue instead of native Java implementation
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.PriorityQueue<Integer> queue = 
            new edu.emory.mathcs.backport.java.util.PriorityQueue<>();
        queue.add(10);
        queue.add(5);
        System.out.println("First element: " + queue.poll());
    }

    public void bad_case_7() {
        // Using backported CountDownLatch instead of native Java implementation
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.CountDownLatch latch = 
            new edu.emory.mathcs.backport.java.util.concurrent.CountDownLatch(1);
        latch.countDown();
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_8() {
        // Using backported Semaphore instead of native Java implementation
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.Semaphore semaphore = 
            new edu.emory.mathcs.backport.java.util.concurrent.Semaphore(5);
        try {
            semaphore.acquire();
            System.out.println("Resource acquired");
            semaphore.release();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_9() {
        // Using backported LinkedBlockingQueue instead of native Java implementation
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.LinkedBlockingQueue<String> queue = 
            new edu.emory.mathcs.backport.java.util.concurrent.LinkedBlockingQueue<>();
        queue.offer("item");
        System.out.println("Queue size: " + queue.size());
    }

    public void bad_case_10() {
        // Using backported CopyOnWriteArrayList instead of native Java implementation
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.CopyOnWriteArrayList<String> list = 
            new edu.emory.mathcs.backport.java.util.concurrent.CopyOnWriteArrayList<>();
        list.add("item");
        System.out.println("List size: " + list.size());
    }

    public void bad_case_11() {
        // Using backported ReentrantReadWriteLock instead of native Java implementation
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.locks.ReentrantReadWriteLock lock = 
            new edu.emory.mathcs.backport.java.util.concurrent.locks.ReentrantReadWriteLock();
        lock.readLock().lock();
        try {
            System.out.println("Reading data");
        } finally {
            lock.readLock().unlock();
        }
    }

    public void bad_case_12() {
        // Using backported DelayQueue instead of native Java implementation
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.DelayQueue<DelayedElement> queue = 
            new edu.emory.mathcs.backport.java.util.concurrent.DelayQueue<>();
        System.out.println("Queue created");
    }

    public void bad_case_13() {
        // Using backported Future interface instead of native Java implementation
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.Future<String> future = null;
        if (future != null && future.isDone()) {
            try {
                String result = future.get();
                System.out.println("Result: " + result);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public void bad_case_14() {
        // Using backported ConcurrentLinkedQueue instead of native Java implementation
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.ConcurrentLinkedQueue<String> queue = 
            new edu.emory.mathcs.backport.java.util.concurrent.ConcurrentLinkedQueue<>();
        queue.add("item");
        System.out.println("Queue size: " + queue.size());
    }

    public void bad_case_15() {
        // Using backported ScheduledThreadPoolExecutor instead of native Java implementation
        // ruleid: java-native-api
        edu.emory.mathcs.backport.java.util.concurrent.ScheduledThreadPoolExecutor executor = 
            new edu.emory.mathcs.backport.java.util.concurrent.ScheduledThreadPoolExecutor(5);
        executor.schedule(() -> System.out.println("Task executed"), 
                         10, 
                         edu.emory.mathcs.backport.java.util.concurrent.TimeUnit.SECONDS);
    }

    // True Negative Examples (safe/secure code that MUST NOT be detected)

    public void good_case_1() {
        // Using native Java ConcurrentHashMap
        // ok: java-native-api
        java.util.concurrent.ConcurrentHashMap<String, String> map = 
            new java.util.concurrent.ConcurrentHashMap<>();
        map.put("key", "value");
        System.out.println("Value: " + map.get("key"));
    }

    public void good_case_2() {
        // Using native Java ArrayBlockingQueue
        // ok: java-native-api
        java.util.concurrent.ArrayBlockingQueue<String> queue = 
            new java.util.concurrent.ArrayBlockingQueue<>(10);
        queue.add("item");
        System.out.println("Queue size: " + queue.size());
    }

    public void good_case_3() {
        // Using native Java ReentrantLock
        // ok: java-native-api
        java.util.concurrent.locks.ReentrantLock lock = 
            new java.util.concurrent.locks.ReentrantLock();
        lock.lock();
        try {
            System.out.println("Critical section");
        } finally {
            lock.unlock();
        }
    }

    public void good_case_4() {
        // Using native Java Callable interface
        // ok: java-native-api
        java.util.concurrent.Callable<String> callable = 
            new java.util.concurrent.Callable<String>() {
                public String call() throws Exception {
                    return "Result";
                }
            };
        System.out.println("Created callable");
    }

    public void good_case_5() {
        // Using native Java ThreadPoolExecutor
        // ok: java-native-api
        java.util.concurrent.ThreadPoolExecutor executor = 
            new java.util.concurrent.ThreadPoolExecutor(
                5, 10, 60, java.util.concurrent.TimeUnit.SECONDS,
                new java.util.concurrent.LinkedBlockingQueue<>());
        executor.shutdown();
    }

    public void good_case_6() {
        // Using native Java PriorityQueue
        // ok: java-native-api
        java.util.PriorityQueue<Integer> queue = new java.util.PriorityQueue<>();
        queue.add(10);
        queue.add(5);
        System.out.println("First element: " + queue.poll());
    }

    public void good_case_7() {
        // Using native Java CountDownLatch
        // ok: java-native-api
        java.util.concurrent.CountDownLatch latch = 
            new java.util.concurrent.CountDownLatch(1);
        latch.countDown();
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_8() {
        // Using native Java Semaphore
        // ok: java-native-api
        java.util.concurrent.Semaphore semaphore = 
            new java.util.concurrent.Semaphore(5);
        try {
            semaphore.acquire();
            System.out.println("Resource acquired");
            semaphore.release();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_9() {
        // Using native Java LinkedBlockingQueue
        // ok: java-native-api
        java.util.concurrent.LinkedBlockingQueue<String> queue = 
            new java.util.concurrent.LinkedBlockingQueue<>();
        queue.offer("item");
        System.out.println("Queue size: " + queue.size());
    }

    public void good_case_10() {
        // Using native Java CopyOnWriteArrayList
        // ok: java-native-api
        java.util.concurrent.CopyOnWriteArrayList<String> list = 
            new java.util.concurrent.CopyOnWriteArrayList<>();
        list.add("item");
        System.out.println("List size: " + list.size());
    }

    public void good_case_11() {
        // Using native Java ReentrantReadWriteLock
        // ok: java-native-api
        java.util.concurrent.locks.ReentrantReadWriteLock lock = 
            new java.util.concurrent.locks.ReentrantReadWriteLock();
        lock.readLock().lock();
        try {
            System.out.println("Reading data");
        } finally {
            lock.readLock().unlock();
        }
    }

    public void good_case_12() {
        // Using native Java DelayQueue
        // ok: java-native-api
        java.util.concurrent.DelayQueue<DelayedElement> queue = 
            new java.util.concurrent.DelayQueue<>();
        System.out.println("Queue created");
    }

    public void good_case_13() {
        // Using native Java Future interface
        // ok: java-native-api
        java.util.concurrent.Future<String> future = null;
        if (future != null && future.isDone()) {
            try {
                String result = future.get();
                System.out.println("Result: " + result);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public void good_case_14() {
        // Using native Java ConcurrentLinkedQueue
        // ok: java-native-api
        java.util.concurrent.ConcurrentLinkedQueue<String> queue = 
            new java.util.concurrent.ConcurrentLinkedQueue<>();
        queue.add("item");
        System.out.println("Queue size: " + queue.size());
    }

    public void good_case_15() {
        // Using native Java ScheduledThreadPoolExecutor
        // ok: java-native-api
        java.util.concurrent.ScheduledThreadPoolExecutor executor = 
            new java.util.concurrent.ScheduledThreadPoolExecutor(5);
        executor.schedule(() -> System.out.println("Task executed"), 
                         10, 
                         java.util.concurrent.TimeUnit.SECONDS);
    }

    // Helper class for DelayQueue examples
    static class DelayedElement implements Delayed {
        private final long delayUntil;
        
        public DelayedElement(long delayInMillis) {
            this.delayUntil = System.currentTimeMillis() + delayInMillis;
        }
        
        @Override
        public long getDelay(TimeUnit unit) {
            long diff = delayUntil - System.currentTimeMillis();
            return unit.convert(diff, TimeUnit.MILLISECONDS);
        }
        
        @Override
        public int compareTo(Delayed o) {
            if (o == this) {
                return 0;
            }
            long diff = getDelay(TimeUnit.MILLISECONDS) - o.getDelay(TimeUnit.MILLISECONDS);
            return (diff == 0) ? 0 : ((diff < 0) ? -1 : 1);
        }
    }
}
// {/fact}