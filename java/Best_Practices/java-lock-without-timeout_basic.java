import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Semaphore;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.HashMap;
import java.util.Map;

public class LockTimeoutExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1() {
        Lock lock = new ReentrantLock();
        try {
            // ruleid: java-lock-without-timeout
            lock.lock(); // Acquiring lock without timeout
            // Critical section
            System.out.println("Executing critical section");
        } finally {
            lock.unlock();
        }
    }

    public void bad_case_2() {
        ReadWriteLock rwLock = new ReentrantReadWriteLock();
        Lock readLock = rwLock.readLock();
        try {
            // ruleid: java-lock-without-timeout
            readLock.lock(); // Read lock without timeout
            // Read operation
            System.out.println("Reading shared resource");
        } finally {
            readLock.unlock();
        }
    }

    public void bad_case_3() {
        ReadWriteLock rwLock = new ReentrantReadWriteLock();
        Lock writeLock = rwLock.writeLock();
        try {
            // ruleid: java-lock-without-timeout
            writeLock.lock(); // Write lock without timeout
            // Write operation
            System.out.println("Writing to shared resource");
        } finally {
            writeLock.unlock();
        }
    }

    public void bad_case_4() {
        Lock lock = new ReentrantLock();
        Condition condition = lock.newCondition();
        try {
            // ruleid: java-lock-without-timeout
            lock.lock();
            while (!isConditionMet()) {
                // ruleid: java-lock-without-timeout
                condition.await(); // Waiting without timeout
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            lock.unlock();
        }
    }

    public void bad_case_5() {
        Semaphore semaphore = new Semaphore(1);
        try {
            // ruleid: java-lock-without-timeout
            semaphore.acquire(); // Acquiring semaphore without timeout
            // Critical section
            System.out.println("Executing critical section with semaphore");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            semaphore.release();
        }
    }

    public void bad_case_6() {
        CountDownLatch latch = new CountDownLatch(1);
        try {
            // Start some work in another thread
            new Thread(() -> {
                try {
                    Thread.sleep(1000);
                    latch.countDown();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }).start();
            
            // ruleid: java-lock-without-timeout
            latch.await(); // Waiting for latch without timeout
            System.out.println("Latch released, continuing execution");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_7() {
        CyclicBarrier barrier = new CyclicBarrier(2);
        try {
            // Start another thread
            new Thread(() -> {
                try {
                    Thread.sleep(5000); // Simulating long operation
                    barrier.await();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
            
            // ruleid: java-lock-without-timeout
            barrier.await(); // Waiting at barrier without timeout
            System.out.println("All threads reached barrier, continuing execution");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        BlockingQueue<String> queue = new LinkedBlockingQueue<>();
        try {
            // ruleid: java-lock-without-timeout
            String item = queue.take(); // Blocking take without timeout
            System.out.println("Retrieved item: " + item);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_9() {
        BlockingQueue<String> queue = new ArrayBlockingQueue<>(10);
        String item = "test";
        try {
            // ruleid: java-lock-without-timeout
            queue.put(item); // Blocking put without timeout
            System.out.println("Added item to queue");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_10() {
        Lock lock = new ReentrantLock(true); // Fair lock
        try {
            // ruleid: java-lock-without-timeout
            lock.lockInterruptibly(); // Interruptible but still no timeout
            // Critical section
            System.out.println("Executing critical section with interruptible lock");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            lock.unlock();
        }
    }

    public void bad_case_11() {
        final Object mutex = new Object();
        try {
            synchronized(mutex) {
                // ruleid: java-lock-without-timeout
                mutex.wait(); // Waiting without timeout
                System.out.println("Mutex notified, continuing execution");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_12() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<String> future = executor.submit(() -> {
            Thread.sleep(10000); // Simulating long operation
            return "Result";
        });
        
        try {
            // ruleid: java-lock-without-timeout
            String result = future.get(); // Waiting for result without timeout
            System.out.println("Got result: " + result);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            executor.shutdown();
        }
    }

    public void bad_case_13() {
        Thread workerThread = new Thread(() -> {
            try {
                Thread.sleep(5000); // Simulating work
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        
        workerThread.start();
        try {
            // ruleid: java-lock-without-timeout
            workerThread.join(); // Waiting for thread completion without timeout
            System.out.println("Worker thread completed");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_14() {
        Map<String, Lock> lockMap = new HashMap<>();
        lockMap.put("resource1", new ReentrantLock());
        
        Lock resourceLock = lockMap.get("resource1");
        try {
            // ruleid: java-lock-without-timeout
            resourceLock.lock(); // Lock from map without timeout
            // Critical section
            System.out.println("Accessing resource1");
        } finally {
            resourceLock.unlock();
        }
    }

    public void bad_case_15() {
        class CustomLockManager {
            private final Lock lock = new ReentrantLock();
            
            public void acquireLock() {
                // ruleid: java-lock-without-timeout
                lock.lock(); // Custom manager without timeout
            }
            
            public void releaseLock() {
                lock.unlock();
            }
        }
        
        CustomLockManager lockManager = new CustomLockManager();
        try {
            lockManager.acquireLock();
            // Critical section
            System.out.println("Executing with custom lock manager");
        } finally {
            lockManager.releaseLock();
        }
    }

    // True Negative Examples (Safe Code)

    public void good_case_1() {
        Lock lock = new ReentrantLock();
        try {
            // ok: java-lock-without-timeout
            boolean acquired = lock.tryLock(1000, TimeUnit.MILLISECONDS); // Using timeout
            if (acquired) {
                try {
                    // Critical section
                    System.out.println("Executing critical section");
                } finally {
                    lock.unlock();
                }
            } else {
                System.out.println("Could not acquire lock, taking alternative action");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_2() {
        ReadWriteLock rwLock = new ReentrantReadWriteLock();
        Lock readLock = rwLock.readLock();
        try {
            // ok: java-lock-without-timeout
            boolean acquired = readLock.tryLock(500, TimeUnit.MILLISECONDS); // Read lock with timeout
            if (acquired) {
                try {
                    // Read operation
                    System.out.println("Reading shared resource");
                } finally {
                    readLock.unlock();
                }
            } else {
                System.out.println("Could not acquire read lock");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_3() {
        ReadWriteLock rwLock = new ReentrantReadWriteLock();
        Lock writeLock = rwLock.writeLock();
        try {
            // ok: java-lock-without-timeout
            boolean acquired = writeLock.tryLock(2, TimeUnit.SECONDS); // Write lock with timeout
            if (acquired) {
                try {
                    // Write operation
                    System.out.println("Writing to shared resource");
                } finally {
                    writeLock.unlock();
                }
            } else {
                System.out.println("Could not acquire write lock");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_4() {
        Lock lock = new ReentrantLock();
        Condition condition = lock.newCondition();
        try {
            // ok: java-lock-without-timeout
            if (lock.tryLock(1, TimeUnit.SECONDS)) {
                try {
                    while (!isConditionMet()) {
                        // ok: java-lock-without-timeout
                        boolean signaled = condition.await(500, TimeUnit.MILLISECONDS); // Waiting with timeout
                        if (!signaled) {
                            System.out.println("Condition wait timed out, checking condition again");
                        }
                    }
                } finally {
                    lock.unlock();
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_5() {
        Semaphore semaphore = new Semaphore(1);
        try {
            // ok: java-lock-without-timeout
            boolean acquired = semaphore.tryAcquire(1, TimeUnit.SECONDS); // Acquiring semaphore with timeout
            if (acquired) {
                try {
                    // Critical section
                    System.out.println("Executing critical section with semaphore");
                } finally {
                    semaphore.release();
                }
            } else {
                System.out.println("Could not acquire semaphore");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_6() {
        CountDownLatch latch = new CountDownLatch(1);
        // Start some work in another thread
        new Thread(() -> {
            try {
                Thread.sleep(1000);
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
        
        try {
            // ok: java-lock-without-timeout
            boolean completed = latch.await(2, TimeUnit.SECONDS); // Waiting for latch with timeout
            if (completed) {
                System.out.println("Latch released, continuing execution");
            } else {
                System.out.println("Latch wait timed out");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_7() {
        CyclicBarrier barrier = new CyclicBarrier(2);
        // Start another thread
        new Thread(() -> {
            try {
                Thread.sleep(5000); // Simulating long operation
                barrier.await(3, TimeUnit.SECONDS);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
        
        try {
            // ok: java-lock-without-timeout
            barrier.await(3, TimeUnit.SECONDS); // Waiting at barrier with timeout
            System.out.println("All threads reached barrier or timeout occurred");
        } catch (Exception e) {
            System.out.println("Barrier wait interrupted or timed out");
        }
    }

    public void good_case_8() {
        BlockingQueue<String> queue = new LinkedBlockingQueue<>();
        try {
            // ok: java-lock-without-timeout
            String item = queue.poll(1, TimeUnit.SECONDS); // Non-blocking take with timeout
            if (item != null) {
                System.out.println("Retrieved item: " + item);
            } else {
                System.out.println("No item available within timeout");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_9() {
        BlockingQueue<String> queue = new ArrayBlockingQueue<>(10);
        String item = "test";
        try {
            // ok: java-lock-without-timeout
            boolean added = queue.offer(item, 1, TimeUnit.SECONDS); // Non-blocking put with timeout
            if (added) {
                System.out.println("Added item to queue");
            } else {
                System.out.println("Could not add item to queue within timeout");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_10() {
        Lock lock = new ReentrantLock();
        try {
            // ok: java-lock-without-timeout
            boolean acquired = lock.tryLock(); // Non-blocking attempt
            if (acquired) {
                try {
                    // Critical section
                    System.out.println("Executing critical section");
                } finally {
                    lock.unlock();
                }
            } else {
                System.out.println("Lock not available, taking alternative action");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        final Object mutex = new Object();
        try {
            synchronized(mutex) {
                // ok: java-lock-without-timeout
                mutex.wait(1000); // Waiting with timeout
                System.out.println("Mutex notified or timed out, continuing execution");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_12() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<String> future = executor.submit(() -> {
            Thread.sleep(10000); // Simulating long operation
            return "Result";
        });
        
        try {
            // ok: java-lock-without-timeout
            String result = future.get(2, TimeUnit.SECONDS); // Waiting for result with timeout
            System.out.println("Got result: " + result);
        } catch (Exception e) {
            System.out.println("Operation timed out or was interrupted");
        } finally {
            executor.shutdown();
        }
    }

    public void good_case_13() {
        Thread workerThread = new Thread(() -> {
            try {
                Thread.sleep(5000); // Simulating work
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        
        workerThread.start();
        try {
            // ok: java-lock-without-timeout
            workerThread.join(2000); // Waiting for thread completion with timeout
            if (workerThread.isAlive()) {
                System.out.println("Worker thread still running after timeout");
            } else {
                System.out.println("Worker thread completed within timeout");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_14() {
        Map<String, Lock> lockMap = new HashMap<>();
        lockMap.put("resource1", new ReentrantLock());
        
        Lock resourceLock = lockMap.get("resource1");
        try {
            // ok: java-lock-without-timeout
            boolean acquired = resourceLock.tryLock(500, TimeUnit.MILLISECONDS); // Lock from map with timeout
            if (acquired) {
                try {
                    // Critical section
                    System.out.println("Accessing resource1");
                } finally {
                    resourceLock.unlock();
                }
            } else {
                System.out.println("Could not acquire resource lock");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_15() {
        class CustomLockManager {
            private final Lock lock = new ReentrantLock();
            
            public boolean acquireLock(long timeout, TimeUnit unit) throws InterruptedException {
                // ok: java-lock-without-timeout
                return lock.tryLock(timeout, unit); // Custom manager with timeout
            }
            
            public void releaseLock() {
                lock.unlock();
            }
        }
        
        CustomLockManager lockManager = new CustomLockManager();
        try {
            boolean acquired = lockManager.acquireLock(1, TimeUnit.SECONDS);
            if (acquired) {
                try {
                    // Critical section
                    System.out.println("Executing with custom lock manager");
                } finally {
                    lockManager.releaseLock();
                }
            } else {
                System.out.println("Could not acquire custom lock");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // Helper method
    private boolean isConditionMet() {
        return Math.random() > 0.5;
    }
}
// {/fact}