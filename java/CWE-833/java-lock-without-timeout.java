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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.HashMap;
import java.util.Map;

public class LockTimeoutExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=concurrency-deadlock@v1.0 defects=1}
    public void bad_case_1() {
        Lock lock = new ReentrantLock();
        try {
            // ruleid: java-lock-without-timeout
            lock.lock(); // Acquiring lock without timeout
            // Critical section
            System.out.println("Processing critical section");
        } finally {
            lock.unlock();
        }
    }

    public void bad_case_2() {
        ReentrantLock lock = new ReentrantLock();
        try {
            // ruleid: java-lock-without-timeout
            lock.lockInterruptibly(); // Still no timeout, just interruptible
            // Critical section
            performDatabaseOperation();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            if (lock.isHeldByCurrentThread()) {
                lock.unlock();
            }
        }
    }

    public void bad_case_3() {
        ReadWriteLock rwLock = new ReentrantReadWriteLock();
        Lock readLock = rwLock.readLock();
        
        try {
            // ruleid: java-lock-without-timeout
            readLock.lock(); // Read lock without timeout
            // Read operation
            readSharedData();
        } finally {
            readLock.unlock();
        }
    }

    public void bad_case_4() {
        ReadWriteLock rwLock = new ReentrantReadWriteLock();
        Lock writeLock = rwLock.writeLock();
        
        try {
            // ruleid: java-lock-without-timeout
            writeLock.lock(); // Write lock without timeout
            // Write operation
            updateSharedData();
        } finally {
            writeLock.unlock();
        }
    }

    public void bad_case_5() {
        final Lock lock = new ReentrantLock();
        Runnable task = () -> {
            try {
                // ruleid: java-lock-without-timeout
                lock.lock(); // Lock in a Runnable without timeout
                processTask();
            } finally {
                lock.unlock();
            }
        };
        new Thread(task).start();
    }

    public void bad_case_6() {
        Lock lock = new ReentrantLock();
        Condition condition = lock.newCondition();
        
        try {
            // ruleid: java-lock-without-timeout
            lock.lock();
            while (!isDataReady()) {
                // ruleid: java-lock-without-timeout
                condition.await(); // Waiting without timeout
            }
            processData();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            lock.unlock();
        }
    }

    public void bad_case_7() {
        Semaphore semaphore = new Semaphore(1);
        try {
            // ruleid: java-lock-without-timeout
            semaphore.acquire(); // Acquiring semaphore without timeout
            accessSharedResource();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            semaphore.release();
        }
    }

    public void bad_case_8() {
        CountDownLatch startSignal = new CountDownLatch(1);
        try {
            // ruleid: java-lock-without-timeout
            startSignal.await(); // Waiting without timeout
            startProcessing();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_9() {
        CyclicBarrier barrier = new CyclicBarrier(3);
        try {
            // ruleid: java-lock-without-timeout
            barrier.await(); // Waiting at barrier without timeout
            performSynchronizedTask();
        } catch (Exception e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_10() {
        BlockingQueue<String> queue = new LinkedBlockingQueue<>();
        try {
            // ruleid: java-lock-without-timeout
            String item = queue.take(); // Blocking take without timeout
            processQueueItem(item);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_11() {
        BlockingQueue<String> queue = new ArrayBlockingQueue<>(10);
        String item = "test";
        try {
            // ruleid: java-lock-without-timeout
            queue.put(item); // Blocking put without timeout
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_12() {
        Lock lock = new ReentrantLock();
        if (isHighPriorityTask()) {
            try {
                // ruleid: java-lock-without-timeout
                lock.lock(); // Conditional lock without timeout
                executeHighPriorityTask();
            } finally {
                lock.unlock();
            }
        } else {
            executeNormalTask();
        }
    }

    public void bad_case_13() {
        Map<String, Lock> lockMap = new HashMap<>();
        lockMap.put("resource1", new ReentrantLock());
        
        String resourceId = getResourceId();
        Lock resourceLock = lockMap.get(resourceId);
        
        try {
            // ruleid: java-lock-without-timeout
            resourceLock.lock(); // Dynamic lock selection without timeout
            accessResource(resourceId);
        } finally {
            resourceLock.unlock();
        }
    }

    public void bad_case_14() {
        ExecutorService executor = Executors.newFixedThreadPool(5);
        Lock lock = new ReentrantLock();
        
        executor.submit(() -> {
            try {
                // ruleid: java-lock-without-timeout
                lock.lock(); // Lock in executor task without timeout
                performLongRunningTask();
            } finally {
                lock.unlock();
            }
        });
    }

    public void bad_case_15() {
        class ResourceManager {
            private final Lock lock = new ReentrantLock();
            
            public void accessResource() {
                try {
                    // ruleid: java-lock-without-timeout
                    lock.lock(); // Lock in inner class without timeout
                    updateResourceState();
                } finally {
                    lock.unlock();
                }
            }
        }
        
        new ResourceManager().accessResource();
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
                    System.out.println("Processing critical section");
                } finally {
                    lock.unlock();
                }
            } else {
                // Handle lock acquisition failure
                System.out.println("Could not acquire lock, trying alternative approach");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_2() {
        ReentrantLock lock = new ReentrantLock();
        try {
            // ok: java-lock-without-timeout
            if (lock.tryLock(500, TimeUnit.MILLISECONDS)) { // Using timeout with conditional
                try {
                    performDatabaseOperation();
                } finally {
                    lock.unlock();
                }
            } else {
                handleLockTimeout();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_3() {
        ReadWriteLock rwLock = new ReentrantReadWriteLock();
        Lock readLock = rwLock.readLock();
        
        try {
            // ok: java-lock-without-timeout
            if (readLock.tryLock(2, TimeUnit.SECONDS)) { // Read lock with timeout
                try {
                    readSharedData();
                } finally {
                    readLock.unlock();
                }
            } else {
                logReadLockFailure();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_4() {
        ReadWriteLock rwLock = new ReentrantReadWriteLock();
        Lock writeLock = rwLock.writeLock();
        
        try {
            // ok: java-lock-without-timeout
            if (writeLock.tryLock(3, TimeUnit.SECONDS)) { // Write lock with timeout
                try {
                    updateSharedData();
                } finally {
                    writeLock.unlock();
                }
            } else {
                queueUpdateForLater();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_5() {
        final Lock lock = new ReentrantLock();
        Runnable task = () -> {
            try {
                // ok: java-lock-without-timeout
                boolean acquired = lock.tryLock(1500, TimeUnit.MILLISECONDS); // Lock in Runnable with timeout
                if (acquired) {
                    try {
                        processTask();
                    } finally {
                        lock.unlock();
                    }
                } else {
                    reportLockAcquisitionFailure();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        };
        new Thread(task).start();
    }

    public void good_case_6() {
        Lock lock = new ReentrantLock();
        Condition condition = lock.newCondition();
        
        try {
            // ok: java-lock-without-timeout
            if (lock.tryLock(1, TimeUnit.SECONDS)) {
                try {
                    while (!isDataReady()) {
                        // ok: java-lock-without-timeout
                        if (!condition.await(500, TimeUnit.MILLISECONDS)) { // Condition await with timeout
                            break; // Timeout occurred
                        }
                    }
                    if (isDataReady()) {
                        processData();
                    } else {
                        handleTimeout();
                    }
                } finally {
                    lock.unlock();
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_7() {
        Semaphore semaphore = new Semaphore(1);
        try {
            // ok: java-lock-without-timeout
            if (semaphore.tryAcquire(2, TimeUnit.SECONDS)) { // Semaphore with timeout
                try {
                    accessSharedResource();
                } finally {
                    semaphore.release();
                }
            } else {
                handleResourceUnavailable();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_8() {
        CountDownLatch startSignal = new CountDownLatch(1);
        try {
            // ok: java-lock-without-timeout
            if (startSignal.await(5, TimeUnit.SECONDS)) { // CountDownLatch with timeout
                startProcessing();
            } else {
                handleStartSignalTimeout();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_9() {
        CyclicBarrier barrier = new CyclicBarrier(3);
        try {
            // ok: java-lock-without-timeout
            barrier.await(3, TimeUnit.SECONDS); // CyclicBarrier with timeout
            performSynchronizedTask();
        } catch (Exception e) {
            handleBarrierException(e);
        }
    }

    public void good_case_10() {
        BlockingQueue<String> queue = new LinkedBlockingQueue<>();
        try {
            // ok: java-lock-without-timeout
            String item = queue.poll(1, TimeUnit.SECONDS); // Queue poll with timeout
            if (item != null) {
                processQueueItem(item);
            } else {
                handleEmptyQueue();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_11() {
        BlockingQueue<String> queue = new ArrayBlockingQueue<>(10);
        String item = "test";
        try {
            // ok: java-lock-without-timeout
            boolean success = queue.offer(item, 2, TimeUnit.SECONDS); // Queue offer with timeout
            if (!success) {
                handleQueueFull();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_12() {
        Lock lock = new ReentrantLock();
        if (isHighPriorityTask()) {
            try {
                // ok: java-lock-without-timeout
                if (lock.tryLock(1500, TimeUnit.MILLISECONDS)) { // Conditional lock with timeout
                    try {
                        executeHighPriorityTask();
                    } finally {
                        lock.unlock();
                    }
                } else {
                    executeAlternativeHighPriorityTask();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        } else {
            executeNormalTask();
        }
    }

    public void good_case_13() {
        Map<String, Lock> lockMap = new HashMap<>();
        lockMap.put("resource1", new ReentrantLock());
        
        String resourceId = getResourceId();
        Lock resourceLock = lockMap.get(resourceId);
        
        try {
            // ok: java-lock-without-timeout
            if (resourceLock.tryLock(800, TimeUnit.MILLISECONDS)) { // Dynamic lock selection with timeout
                try {
                    accessResource(resourceId);
                } finally {
                    resourceLock.unlock();
                }
            } else {
                queueResourceAccess(resourceId);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_14() {
        ExecutorService executor = Executors.newFixedThreadPool(5);
        Lock lock = new ReentrantLock();
        
        executor.submit(() -> {
            try {
                // ok: java-lock-without-timeout
                if (lock.tryLock(2, TimeUnit.SECONDS)) { // Lock in executor task with timeout
                    try {
                        performLongRunningTask();
                    } finally {
                        lock.unlock();
                    }
                } else {
                    logTaskSkipped();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
    }

    public void good_case_15() {
        class ResourceManager {
            private final Lock lock = new ReentrantLock();
            
            public void accessResource() {
                try {
                    // ok: java-lock-without-timeout
                    if (lock.tryLock(1, TimeUnit.SECONDS)) { // Lock in inner class with timeout
                        try {
                            updateResourceState();
                        } finally {
                            lock.unlock();
                        }
                    } else {
                        handleResourceBusy();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        
        new ResourceManager().accessResource();
    }

    // Helper methods to make the examples compile
    private void performDatabaseOperation() {}
    private void readSharedData() {}
    private void updateSharedData() {}
    private void processTask() {}
    private boolean isDataReady() { return false; }
    private void processData() {}
    private void accessSharedResource() {}
    private void startProcessing() {}
    private void performSynchronizedTask() {}
    private void processQueueItem(String item) {}
    private boolean isHighPriorityTask() { return false; }
    private void executeHighPriorityTask() {}
    private void executeNormalTask() {}
    private String getResourceId() { return "resource1"; }
    private void accessResource(String resourceId) {}
    private void performLongRunningTask() {}
    private void updateResourceState() {}
    private void handleLockTimeout() {}
    private void logReadLockFailure() {}
    private void queueUpdateForLater() {}
    private void reportLockAcquisitionFailure() {}
    private void handleTimeout() {}
    private void handleResourceUnavailable() {}
    private void handleStartSignalTimeout() {}
    private void handleBarrierException(Exception e) {}
    private void handleEmptyQueue() {}
    private void handleQueueFull() {}
    private void executeAlternativeHighPriorityTask() {}
    private void queueResourceAccess(String resourceId) {}
    private void logTaskSkipped() {}
    private void handleResourceBusy() {}
}
// {/fact}