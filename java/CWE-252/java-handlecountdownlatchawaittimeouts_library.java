import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Semaphore;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.DelayQueue;
import java.util.concurrent.Delayed;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.concurrent.Phaser;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;
import java.util.Optional;
import java.util.List;
import java.util.ArrayList;
import java.time.Duration;
import java.io.IOException;

// Security Issue: Not checking the result of CountDownLatch.await() with timeout can lead to race conditions and 
// unexpected behavior when the latch doesn't count down within the expected time frame.

// True Positive Examples (Vulnerable/Insecure Code)

public class CountDownLatchAwaitTimeoutExamples {

    // Basic CountDownLatch usage without checking await result
// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
    public void bad_case_1() {
        CountDownLatch latch = new CountDownLatch(1);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        
        executor.submit(() -> {
            try {
                Thread.sleep(2000);
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(1, TimeUnit.SECONDS);
            // Continues execution regardless of whether the latch counted down
            System.out.println("Task completed");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            executor.shutdown();
        }
    }
    
    // Using CountDownLatch with ExecutorService for task completion
    public void bad_case_2() {
        CountDownLatch latch = new CountDownLatch(3);
        ExecutorService executor = Executors.newFixedThreadPool(3);
        
        for (int i = 0; i < 3; i++) {
            executor.submit(() -> {
                try {
                    Thread.sleep((long) (Math.random() * 2000));
                    latch.countDown();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(500, TimeUnit.MILLISECONDS);
            // Continues without verifying all tasks completed
            System.out.println("All tasks should be completed");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            executor.shutdown();
        }
    }
    
    // Using CountDownLatch with ThreadPoolExecutor
    public void bad_case_3() {
        CountDownLatch latch = new CountDownLatch(5);
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
            2, 5, 60, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
        
        for (int i = 0; i < 5; i++) {
            executor.execute(() -> {
                try {
                    Thread.sleep(1500);
                    latch.countDown();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(1, TimeUnit.SECONDS);
            // Proceeds without checking if all threads completed
            System.out.println("Processing complete");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            executor.shutdown();
        }
    }
    
    // Using CountDownLatch with ScheduledExecutorService
    public void bad_case_4() {
        CountDownLatch latch = new CountDownLatch(1);
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        
        scheduler.schedule(() -> {
            latch.countDown();
        }, 2, TimeUnit.SECONDS);
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(1, TimeUnit.SECONDS);
            // Continues without checking if scheduled task executed
            System.out.println("Scheduled task executed");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            scheduler.shutdown();
        }
    }
    
    // Using CountDownLatch with CompletableFuture
    public void bad_case_5() {
        CountDownLatch latch = new CountDownLatch(1);
        
        CompletableFuture.runAsync(() -> {
            try {
                Thread.sleep(2000);
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(1, TimeUnit.SECONDS);
            // Continues without checking if async task completed
            System.out.println("Async task completed");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with Phaser for synchronization
    public void bad_case_6() {
        CountDownLatch latch = new CountDownLatch(1);
        Phaser phaser = new Phaser(1);
        
        Thread worker = new Thread(() -> {
            phaser.arriveAndAwaitAdvance();
            try {
                Thread.sleep(2000);
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        worker.start();
        
        phaser.arriveAndDeregister();
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(1, TimeUnit.SECONDS);
            // Continues without checking if worker thread completed
            System.out.println("Worker completed");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with CyclicBarrier
    public void bad_case_7() {
        final CountDownLatch latch = new CountDownLatch(1);
        final CyclicBarrier barrier = new CyclicBarrier(2);
        
        Thread worker = new Thread(() -> {
            try {
                barrier.await();
                Thread.sleep(2000);
                latch.countDown();
            } catch (Exception e) {
                Thread.currentThread().interrupt();
            }
        });
        worker.start();
        
        try {
            barrier.await();
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(1, TimeUnit.SECONDS);
            // Continues without checking if worker completed
            System.out.println("Worker task completed");
        } catch (Exception e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with Semaphore
    public void bad_case_8() {
        CountDownLatch latch = new CountDownLatch(1);
        Semaphore semaphore = new Semaphore(1);
        
        Thread worker = new Thread(() -> {
            try {
                semaphore.acquire();
                Thread.sleep(2000);
                latch.countDown();
                semaphore.release();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        worker.start();
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(1, TimeUnit.SECONDS);
            // Continues without checking if worker acquired and released semaphore
            System.out.println("Worker completed semaphore operation");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with ReentrantLock
    public void bad_case_9() {
        CountDownLatch latch = new CountDownLatch(1);
        ReentrantLock lock = new ReentrantLock();
        
        Thread worker = new Thread(() -> {
            lock.lock();
            try {
                Thread.sleep(2000);
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                lock.unlock();
            }
        });
        worker.start();
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(1, TimeUnit.SECONDS);
            // Continues without checking if worker completed
            System.out.println("Worker completed lock operation");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with ReadWriteLock
    public void bad_case_10() {
        CountDownLatch latch = new CountDownLatch(1);
        ReadWriteLock rwLock = new ReentrantReadWriteLock();
        
        Thread worker = new Thread(() -> {
            rwLock.writeLock().lock();
            try {
                Thread.sleep(2000);
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                rwLock.writeLock().unlock();
            }
        });
        worker.start();
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(1, TimeUnit.SECONDS);
            // Continues without checking if worker completed
            System.out.println("Worker completed write lock operation");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with ArrayBlockingQueue
    public void bad_case_11() {
        CountDownLatch latch = new CountDownLatch(1);
        ArrayBlockingQueue<String> queue = new ArrayBlockingQueue<>(10);
        
        Thread producer = new Thread(() -> {
            try {
                Thread.sleep(2000);
                queue.put("Message");
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        producer.start();
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(1, TimeUnit.SECONDS);
            // Continues without checking if producer added message
            String message = queue.poll();
            System.out.println("Received: " + message);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with SynchronousQueue
    public void bad_case_12() {
        CountDownLatch latch = new CountDownLatch(1);
        SynchronousQueue<String> queue = new SynchronousQueue<>();
        
        Thread producer = new Thread(() -> {
            try {
                Thread.sleep(2000);
                queue.put("Synchronous Message");
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        producer.start();
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(1, TimeUnit.SECONDS);
            // Continues without checking if producer added message
            String message = queue.poll();
            System.out.println("Received: " + message);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with DelayQueue
    public void bad_case_13() {
        CountDownLatch latch = new CountDownLatch(1);
        DelayQueue<DelayedElement> delayQueue = new DelayQueue<>();
        
        Thread producer = new Thread(() -> {
            try {
                Thread.sleep(2000);
                delayQueue.put(new DelayedElement("Delayed Message", 100));
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        producer.start();
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(1, TimeUnit.SECONDS);
            // Continues without checking if producer added message
            DelayedElement message = delayQueue.poll();
            System.out.println("Received: " + (message != null ? message.getMessage() : "null"));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with PriorityBlockingQueue
    public void bad_case_14() {
        CountDownLatch latch = new CountDownLatch(1);
        PriorityBlockingQueue<Integer> priorityQueue = new PriorityBlockingQueue<>();
        
        Thread producer = new Thread(() -> {
            try {
                Thread.sleep(2000);
                priorityQueue.put(42);
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        producer.start();
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(1, TimeUnit.SECONDS);
            // Continues without checking if producer added number
            Integer value = priorityQueue.poll();
            System.out.println("Received: " + value);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with Condition
    public void bad_case_15() {
        CountDownLatch latch = new CountDownLatch(1);
        Lock lock = new ReentrantLock();
        Condition condition = lock.newCondition();
        AtomicBoolean ready = new AtomicBoolean(false);
        
        Thread signaler = new Thread(() -> {
            try {
                Thread.sleep(2000);
                lock.lock();
                try {
                    ready.set(true);
                    condition.signal();
                    latch.countDown();
                } finally {
                    lock.unlock();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        signaler.start();
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(1, TimeUnit.SECONDS);
            // Continues without checking if condition was signaled
            System.out.println("Condition signaled: " + ready.get());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    // Basic CountDownLatch usage with proper await result checking
    public void good_case_1() {
        CountDownLatch latch = new CountDownLatch(1);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        
        executor.submit(() -> {
            try {
                Thread.sleep(2000);
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean completed = latch.await(1, TimeUnit.SECONDS);
            if (completed) {
                System.out.println("Task completed successfully");
            } else {
                System.out.println("Task timed out");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            executor.shutdown();
        }
    }
    
    // Using CountDownLatch with ExecutorService for task completion with proper checking
    public void good_case_2() {
        CountDownLatch latch = new CountDownLatch(3);
        ExecutorService executor = Executors.newFixedThreadPool(3);
        
        for (int i = 0; i < 3; i++) {
            executor.submit(() -> {
                try {
                    Thread.sleep((long) (Math.random() * 2000));
                    latch.countDown();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean allTasksCompleted = latch.await(500, TimeUnit.MILLISECONDS);
            if (allTasksCompleted) {
                System.out.println("All tasks completed successfully");
            } else {
                System.out.println("Some tasks did not complete in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            executor.shutdown();
        }
    }
    
    // Using CountDownLatch with ThreadPoolExecutor with proper checking
    public void good_case_3() {
        CountDownLatch latch = new CountDownLatch(5);
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
            2, 5, 60, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
        
        for (int i = 0; i < 5; i++) {
            executor.execute(() -> {
                try {
                    Thread.sleep(1500);
                    latch.countDown();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean completed = latch.await(1, TimeUnit.SECONDS);
            if (completed) {
                System.out.println("All threads completed their tasks");
            } else {
                System.out.println("Not all threads completed in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            executor.shutdown();
        }
    }
    
    // Using CountDownLatch with ScheduledExecutorService with proper checking
    public void good_case_4() {
        CountDownLatch latch = new CountDownLatch(1);
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        
        scheduler.schedule(() -> {
            latch.countDown();
        }, 2, TimeUnit.SECONDS);
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean taskExecuted = latch.await(1, TimeUnit.SECONDS);
            if (taskExecuted) {
                System.out.println("Scheduled task executed on time");
            } else {
                System.out.println("Scheduled task did not execute in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            scheduler.shutdown();
        }
    }
    
    // Using CountDownLatch with CompletableFuture with proper checking
    public void good_case_5() {
        CountDownLatch latch = new CountDownLatch(1);
        
        CompletableFuture.runAsync(() -> {
            try {
                Thread.sleep(2000);
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean completed = latch.await(1, TimeUnit.SECONDS);
            if (completed) {
                System.out.println("Async task completed on time");
            } else {
                System.out.println("Async task did not complete in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with Phaser for synchronization with proper checking
    public void good_case_6() {
        CountDownLatch latch = new CountDownLatch(1);
        Phaser phaser = new Phaser(1);
        
        Thread worker = new Thread(() -> {
            phaser.arriveAndAwaitAdvance();
            try {
                Thread.sleep(2000);
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        worker.start();
        
        phaser.arriveAndDeregister();
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean completed = latch.await(1, TimeUnit.SECONDS);
            if (completed) {
                System.out.println("Worker completed on time");
            } else {
                System.out.println("Worker did not complete in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with CyclicBarrier with proper checking
    public void good_case_7() {
        final CountDownLatch latch = new CountDownLatch(1);
        final CyclicBarrier barrier = new CyclicBarrier(2);
        
        Thread worker = new Thread(() -> {
            try {
                barrier.await();
                Thread.sleep(2000);
                latch.countDown();
            } catch (Exception e) {
                Thread.currentThread().interrupt();
            }
        });
        worker.start();
        
        try {
            barrier.await();
            // ok: java-handlecountdownlatchawaittimeouts
            boolean completed = latch.await(1, TimeUnit.SECONDS);
            if (completed) {
                System.out.println("Worker task completed on time");
            } else {
                System.out.println("Worker task did not complete in time");
            }
        } catch (Exception e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with Semaphore with proper checking
    public void good_case_8() {
        CountDownLatch latch = new CountDownLatch(1);
        Semaphore semaphore = new Semaphore(1);
        
        Thread worker = new Thread(() -> {
            try {
                semaphore.acquire();
                Thread.sleep(2000);
                latch.countDown();
                semaphore.release();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        worker.start();
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean completed = latch.await(1, TimeUnit.SECONDS);
            if (completed) {
                System.out.println("Worker completed semaphore operation on time");
            } else {
                System.out.println("Worker did not complete semaphore operation in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with ReentrantLock with proper checking
    public void good_case_9() {
        CountDownLatch latch = new CountDownLatch(1);
        ReentrantLock lock = new ReentrantLock();
        
        Thread worker = new Thread(() -> {
            lock.lock();
            try {
                Thread.sleep(2000);
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                lock.unlock();
            }
        });
        worker.start();
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean completed = latch.await(1, TimeUnit.SECONDS);
            if (completed) {
                System.out.println("Worker completed lock operation on time");
            } else {
                System.out.println("Worker did not complete lock operation in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with ReadWriteLock with proper checking
    public void good_case_10() {
        CountDownLatch latch = new CountDownLatch(1);
        ReadWriteLock rwLock = new ReentrantReadWriteLock();
        
        Thread worker = new Thread(() -> {
            rwLock.writeLock().lock();
            try {
                Thread.sleep(2000);
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                rwLock.writeLock().unlock();
            }
        });
        worker.start();
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean completed = latch.await(1, TimeUnit.SECONDS);
            if (completed) {
                System.out.println("Worker completed write lock operation on time");
            } else {
                System.out.println("Worker did not complete write lock operation in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with ArrayBlockingQueue with proper checking
    public void good_case_11() {
        CountDownLatch latch = new CountDownLatch(1);
        ArrayBlockingQueue<String> queue = new ArrayBlockingQueue<>(10);
        
        Thread producer = new Thread(() -> {
            try {
                Thread.sleep(2000);
                queue.put("Message");
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        producer.start();
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean completed = latch.await(1, TimeUnit.SECONDS);
            if (completed) {
                String message = queue.poll();
                System.out.println("Received: " + message);
            } else {
                System.out.println("Producer did not add message in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with SynchronousQueue with proper checking
    public void good_case_12() {
        CountDownLatch latch = new CountDownLatch(1);
        SynchronousQueue<String> queue = new SynchronousQueue<>();
        
        Thread producer = new Thread(() -> {
            try {
                Thread.sleep(2000);
                queue.put("Synchronous Message");
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        producer.start();
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean completed = latch.await(1, TimeUnit.SECONDS);
            if (completed) {
                String message = queue.poll();
                System.out.println("Received: " + message);
            } else {
                System.out.println("Producer did not add message in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with DelayQueue with proper checking
    public void good_case_13() {
        CountDownLatch latch = new CountDownLatch(1);
        DelayQueue<DelayedElement> delayQueue = new DelayQueue<>();
        
        Thread producer = new Thread(() -> {
            try {
                Thread.sleep(2000);
                delayQueue.put(new DelayedElement("Delayed Message", 100));
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        producer.start();
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean completed = latch.await(1, TimeUnit.SECONDS);
            if (completed) {
                DelayedElement message = delayQueue.poll();
                System.out.println("Received: " + (message != null ? message.getMessage() : "null"));
            } else {
                System.out.println("Producer did not add message in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with PriorityBlockingQueue with proper checking
    public void good_case_14() {
        CountDownLatch latch = new CountDownLatch(1);
        PriorityBlockingQueue<Integer> priorityQueue = new PriorityBlockingQueue<>();
        
        Thread producer = new Thread(() -> {
            try {
                Thread.sleep(2000);
                priorityQueue.put(42);
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        producer.start();
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean completed = latch.await(1, TimeUnit.SECONDS);
            if (completed) {
                Integer value = priorityQueue.poll();
                System.out.println("Received: " + value);
            } else {
                System.out.println("Producer did not add number in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Using CountDownLatch with Condition with proper checking
    public void good_case_15() {
        CountDownLatch latch = new CountDownLatch(1);
        Lock lock = new ReentrantLock();
        Condition condition = lock.newCondition();
        AtomicBoolean ready = new AtomicBoolean(false);
        
        Thread signaler = new Thread(() -> {
            try {
                Thread.sleep(2000);
                lock.lock();
                try {
                    ready.set(true);
                    condition.signal();
                    latch.countDown();
                } finally {
                    lock.unlock();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        signaler.start();
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean completed = latch.await(1, TimeUnit.SECONDS);
            if (completed) {
                System.out.println("Condition was signaled: " + ready.get());
            } else {
                System.out.println("Condition was not signaled in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // Helper class for DelayQueue examples
    static class DelayedElement implements Delayed {
        private final String message;
        private final long endTime;
        
        public DelayedElement(String message, long delayInMillis) {
            this.message = message;
            this.endTime = System.currentTimeMillis() + delayInMillis;
        }
        
        public String getMessage() {
            return message;
        }
        
        @Override
        public long getDelay(TimeUnit unit) {
            long remaining = endTime - System.currentTimeMillis();
            return unit.convert(remaining, TimeUnit.MILLISECONDS);
        }
        
        @Override
        public int compareTo(Delayed other) {
            if (this == other) {
                return 0;
            }
            long diff = getDelay(TimeUnit.MILLISECONDS) - other.getDelay(TimeUnit.MILLISECONDS);
            return Long.compare(diff, 0);
        }
    }
    
    public static void main(String[] args) {
        CountDownLatchAwaitTimeoutExamples examples = new CountDownLatchAwaitTimeoutExamples();
        
        // Run a sample test case
        examples.good_case_1();
    }
}
// {/fact}