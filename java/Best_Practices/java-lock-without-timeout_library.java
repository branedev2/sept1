import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.DelayQueue;
import java.util.concurrent.Delayed;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.TransferQueue;
import java.util.concurrent.LinkedTransferQueue;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicStampedReference;
import java.util.concurrent.atomic.AtomicMarkableReference;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.StampedLock;
import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.framework.recipes.locks.InterProcessMutex;
import org.apache.curator.retry.ExponentialBackoffRetry;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;
import org.redisson.Redisson;
import org.redisson.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.cp.lock.FencedLock;
import org.apache.commons.pool2.impl.GenericObjectPool;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import java.util.concurrent.locks.LockSupport;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.Callable;
import org.apache.zookeeper.ZooKeeper;
import org.apache.zookeeper.data.Stat;
import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.ZooDefs;
import org.apache.zookeeper.KeeperException;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;

// Security Issue: Lock acquisition without timeout can lead to indefinite blocking and service outages

// True Positive Examples (Vulnerable/Insecure Code)
public class LockWithoutTimeoutExamples {

// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1() {
        // ReentrantLock without timeout
        Lock lock = new ReentrantLock();
        try {
            // ruleid: java-lock-without-timeout
            lock.lock();
            // Critical section that might take time
            performOperation();
        } finally {
            lock.unlock();
        }
    }

    public void bad_case_2() {
        // ReentrantReadWriteLock's ReadLock without timeout
        ReadWriteLock rwLock = new ReentrantReadWriteLock();
        Lock readLock = rwLock.readLock();
        try {
            // ruleid: java-lock-without-timeout
            readLock.lock();
            // Read operation that might take time
            readData();
        } finally {
            readLock.unlock();
        }
    }

    public void bad_case_3() {
        // ReentrantReadWriteLock's WriteLock without timeout
        ReadWriteLock rwLock = new ReentrantReadWriteLock();
        Lock writeLock = rwLock.writeLock();
        try {
            // ruleid: java-lock-without-timeout
            writeLock.lock();
            // Write operation that might take time
            writeData();
        } finally {
            writeLock.unlock();
        }
    }

    public void bad_case_4() {
        // Semaphore acquire without timeout
        Semaphore semaphore = new Semaphore(1);
        try {
            // ruleid: java-lock-without-timeout
            semaphore.acquire();
            // Resource access that might take time
            accessResource();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            semaphore.release();
        }
    }

    public void bad_case_5() {
        // CountDownLatch await without timeout
        CountDownLatch latch = new CountDownLatch(1);
        try {
            // ruleid: java-lock-without-timeout
            latch.await();
            // Proceed after latch countdown
            proceedAfterCountdown();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_6() {
        // CyclicBarrier await without timeout
        CyclicBarrier barrier = new CyclicBarrier(2);
        try {
            // ruleid: java-lock-without-timeout
            barrier.await();
            // Proceed after all threads reach barrier
            proceedAfterBarrier();
        } catch (Exception e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_7() {
        // Condition await without timeout
        Lock lock = new ReentrantLock();
        Condition condition = lock.newCondition();
        try {
            lock.lock();
            while (!conditionMet()) {
                // ruleid: java-lock-without-timeout
                condition.await();
            }
            // Proceed after condition is met
            proceedAfterCondition();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            lock.unlock();
        }
    }

    public void bad_case_8() {
        // BlockingQueue take without timeout
        BlockingQueue<String> queue = new LinkedBlockingQueue<>();
        try {
            // ruleid: java-lock-without-timeout
            String item = queue.take();
            // Process the item
            processItem(item);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_9() {
        // TransferQueue transfer without timeout
        TransferQueue<String> transferQueue = new LinkedTransferQueue<>();
        try {
            // ruleid: java-lock-without-timeout
            transferQueue.transfer("data");
            // Continue after transfer completes
            continueAfterTransfer();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_10() {
        // StampedLock writeLock without timeout
        StampedLock stampedLock = new StampedLock();
        long stamp = 0;
        try {
            // ruleid: java-lock-without-timeout
            stamp = stampedLock.writeLock();
            // Write operation that might take time
            writeWithStampedLock();
        } finally {
            stampedLock.unlockWrite(stamp);
        }
    }

    public void bad_case_11() {
        try {
            // Apache Curator InterProcessMutex without timeout
            CuratorFramework client = CuratorFrameworkFactory.newClient(
                    "localhost:2181", 
                    new ExponentialBackoffRetry(1000, 3));
            client.start();
            
            InterProcessMutex mutex = new InterProcessMutex(client, "/mutex-path");
            try {
                // ruleid: java-lock-without-timeout
                mutex.acquire();
                // Distributed critical section
                performDistributedOperation();
            } finally {
                mutex.release();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        // Redisson RLock without timeout
        Config config = new Config();
        config.useSingleServer().setAddress("redis://localhost:6379");
        RedissonClient redisson = Redisson.create(config);
        
        RLock lock = redisson.getLock("myLock");
        try {
            // ruleid: java-lock-without-timeout
            lock.lock();
            // Redis-based critical section
            performRedisOperation();
        } finally {
            lock.unlock();
        }
    }

    public void bad_case_13() {
        // Hazelcast FencedLock without timeout
        HazelcastInstance hazelcastInstance = Hazelcast.newHazelcastInstance();
        FencedLock lock = hazelcastInstance.getCPSubsystem().getLock("my-lock");
        try {
            // ruleid: java-lock-without-timeout
            lock.lock();
            // Distributed critical section
            performHazelcastOperation();
        } finally {
            lock.unlock();
        }
    }

    public void bad_case_14() {
        // Apache Commons Pool borrowObject without timeout
        GenericObjectPoolConfig<String> config = new GenericObjectPoolConfig<>();
        GenericObjectPool<String> pool = new GenericObjectPool<>(new StringPoolableObjectFactory(), config);
        try {
            // ruleid: java-lock-without-timeout
            String obj = pool.borrowObject();
            try {
                // Use the pooled object
                usePooledObject(obj);
            } finally {
                pool.returnObject(obj);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        // ZooKeeper synchronous operations without timeout
        try {
            ZooKeeper zk = new ZooKeeper("localhost:2181", 3000, null);
            // ruleid: java-lock-without-timeout
            Stat stat = zk.exists("/my-node", false);
            if (stat == null) {
                zk.create("/my-node", "data".getBytes(), ZooDefs.Ids.OPEN_AC_REDACTED_TWILIO_ID_UNSAFE, CreateMode.PERSISTENT);
            }
            // Process ZooKeeper node
            processZkNode();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1() {
        // ReentrantLock with timeout
        Lock lock = new ReentrantLock();
        try {
            // ok: java-lock-without-timeout
            boolean acquired = lock.tryLock(5, TimeUnit.SECONDS);
            if (acquired) {
                try {
                    // Critical section that might take time
                    performOperation();
                } finally {
                    lock.unlock();
                }
            } else {
                // Handle lock acquisition failure
                handleLockFailure();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_2() {
        // ReentrantReadWriteLock's ReadLock with timeout
        ReadWriteLock rwLock = new ReentrantReadWriteLock();
        Lock readLock = rwLock.readLock();
        try {
            // ok: java-lock-without-timeout
            boolean acquired = readLock.tryLock(3, TimeUnit.SECONDS);
            if (acquired) {
                try {
                    // Read operation that might take time
                    readData();
                } finally {
                    readLock.unlock();
                }
            } else {
                // Handle lock acquisition failure
                handleReadLockFailure();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_3() {
        // ReentrantReadWriteLock's WriteLock with timeout
        ReadWriteLock rwLock = new ReentrantReadWriteLock();
        Lock writeLock = rwLock.writeLock();
        try {
            // ok: java-lock-without-timeout
            boolean acquired = writeLock.tryLock(4, TimeUnit.SECONDS);
            if (acquired) {
                try {
                    // Write operation that might take time
                    writeData();
                } finally {
                    writeLock.unlock();
                }
            } else {
                // Handle lock acquisition failure
                handleWriteLockFailure();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_4() {
        // Semaphore acquire with timeout
        Semaphore semaphore = new Semaphore(1);
        try {
            // ok: java-lock-without-timeout
            boolean acquired = semaphore.tryAcquire(2, TimeUnit.SECONDS);
            if (acquired) {
                try {
                    // Resource access that might take time
                    accessResource();
                } finally {
                    semaphore.release();
                }
            } else {
                // Handle semaphore acquisition failure
                handleSemaphoreFailure();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_5() {
        // CountDownLatch await with timeout
        CountDownLatch latch = new CountDownLatch(1);
        try {
            // ok: java-lock-without-timeout
            boolean completed = latch.await(5, TimeUnit.SECONDS);
            if (completed) {
                // Proceed after latch countdown
                proceedAfterCountdown();
            } else {
                // Handle timeout
                handleLatchTimeout();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_6() {
        // CyclicBarrier await with timeout
        CyclicBarrier barrier = new CyclicBarrier(2);
        try {
            // ok: java-lock-without-timeout
            barrier.await(3, TimeUnit.SECONDS);
            // Proceed after all threads reach barrier
            proceedAfterBarrier();
        } catch (Exception e) {
            // Handle timeout or interruption
            handleBarrierTimeout();
        }
    }

    public void good_case_7() {
        // Condition await with timeout
        Lock lock = new ReentrantLock();
        Condition condition = lock.newCondition();
        try {
            lock.lock();
            while (!conditionMet()) {
                // ok: java-lock-without-timeout
                boolean signaled = condition.await(2, TimeUnit.SECONDS);
                if (!signaled && !conditionMet()) {
                    // Handle timeout
                    handleConditionTimeout();
                    break;
                }
            }
            // Proceed after condition is met
            proceedAfterCondition();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            lock.unlock();
        }
    }

    public void good_case_8() {
        // BlockingQueue poll with timeout
        BlockingQueue<String> queue = new LinkedBlockingQueue<>();
        try {
            // ok: java-lock-without-timeout
            String item = queue.poll(1, TimeUnit.SECONDS);
            if (item != null) {
                // Process the item
                processItem(item);
            } else {
                // Handle queue empty timeout
                handleQueueEmptyTimeout();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_9() {
        // TransferQueue tryTransfer with timeout
        TransferQueue<String> transferQueue = new LinkedTransferQueue<>();
        try {
            // ok: java-lock-without-timeout
            boolean transferred = transferQueue.tryTransfer("data", 3, TimeUnit.SECONDS);
            if (transferred) {
                // Continue after transfer completes
                continueAfterTransfer();
            } else {
                // Handle transfer timeout
                handleTransferTimeout();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_10() {
        // StampedLock tryWriteLock with timeout
        StampedLock stampedLock = new StampedLock();
        try {
            // ok: java-lock-without-timeout
            long stamp = stampedLock.tryWriteLock(4, TimeUnit.SECONDS);
            if (stamp != 0) {
                try {
                    // Write operation that might take time
                    writeWithStampedLock();
                } finally {
                    stampedLock.unlockWrite(stamp);
                }
            } else {
                // Handle lock acquisition failure
                handleStampedLockFailure();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_11() {
        try {
            // Apache Curator InterProcessMutex with timeout
            CuratorFramework client = CuratorFrameworkFactory.newClient(
                    "localhost:2181", 
                    new ExponentialBackoffRetry(1000, 3));
            client.start();
            
            InterProcessMutex mutex = new InterProcessMutex(client, "/mutex-path");
            try {
                // ok: java-lock-without-timeout
                boolean acquired = mutex.acquire(5, TimeUnit.SECONDS);
                if (acquired) {
                    try {
                        // Distributed critical section
                        performDistributedOperation();
                    } finally {
                        mutex.release();
                    }
                } else {
                    // Handle lock acquisition failure
                    handleCuratorLockFailure();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        // Redisson RLock with timeout
        Config config = new Config();
        config.useSingleServer().setAddress("redis://localhost:6379");
        RedissonClient redisson = Redisson.create(config);
        
        RLock lock = redisson.getLock("myLock");
        try {
            // ok: java-lock-without-timeout
            boolean acquired = lock.tryLock(2, 10, TimeUnit.SECONDS);
            if (acquired) {
                try {
                    // Redis-based critical section
                    performRedisOperation();
                } finally {
                    lock.unlock();
                }
            } else {
                // Handle lock acquisition failure
                handleRedisLockFailure();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_13() {
        // Hazelcast FencedLock with timeout
        HazelcastInstance hazelcastInstance = Hazelcast.newHazelcastInstance();
        FencedLock lock = hazelcastInstance.getCPSubsystem().getLock("my-lock");
        try {
            // ok: java-lock-without-timeout
            boolean acquired = lock.tryLock(3, TimeUnit.SECONDS);
            if (acquired) {
                try {
                    // Distributed critical section
                    performHazelcastOperation();
                } finally {
                    lock.unlock();
                }
            } else {
                // Handle lock acquisition failure
                handleHazelcastLockFailure();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_14() {
        // Apache Commons Pool borrowObject with timeout
        GenericObjectPoolConfig<String> config = new GenericObjectPoolConfig<>();
        GenericObjectPool<String> pool = new GenericObjectPool<>(new StringPoolableObjectFactory(), config);
        try {
            // ok: java-lock-without-timeout
            String obj = pool.borrowObject(2000);
            try {
                // Use the pooled object
                usePooledObject(obj);
            } finally {
                pool.returnObject(obj);
            }
        } catch (Exception e) {
            // Handle timeout or other exceptions
            handlePoolTimeout();
        }
    }

    public void good_case_15() {
        // ZooKeeper operations with timeout using async API
        try {
            ZooKeeper zk = new ZooKeeper("localhost:2181", 3000, null);
            CompletableFuture<Stat> future = new CompletableFuture<>();
            
            // ok: java-lock-without-timeout
            zk.exists("/my-node", false, (rc, path, ctx, stat) -> {
                if (rc == KeeperException.Code.OK.intValue()) {
                    future.complete(stat);
                } else {
                    future.completeExceptionally(KeeperException.create(KeeperException.Code.get(rc)));
                }
            }, null);
            
            try {
                Stat stat = future.get(5, TimeUnit.SECONDS);
                if (stat == null) {
                    zk.create("/my-node", "data".getBytes(), ZooDefs.Ids.OPEN_AC_REDACTED_TWILIO_ID_UNSAFE, CreateMode.PERSISTENT);
                }
                // Process ZooKeeper node
                processZkNode();
            } catch (java.util.concurrent.TimeoutException e) {
                // Handle timeout
                handleZkTimeout();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Helper methods to make the examples complete
    private void performOperation() {}
    private void readData() {}
    private void writeData() {}
    private void accessResource() {}
    private void proceedAfterCountdown() {}
    private void proceedAfterBarrier() {}
    private boolean conditionMet() { return false; }
    private void proceedAfterCondition() {}
    private void processItem(String item) {}
    private void continueAfterTransfer() {}
    private void writeWithStampedLock() {}
    private void performDistributedOperation() {}
    private void performRedisOperation() {}
    private void performHazelcastOperation() {}
    private void usePooledObject(String obj) {}
    private void processZkNode() {}
    private void handleLockFailure() {}
    private void handleReadLockFailure() {}
    private void handleWriteLockFailure() {}
    private void handleSemaphoreFailure() {}
    private void handleLatchTimeout() {}
    private void handleBarrierTimeout() {}
    private void handleConditionTimeout() {}
    private void handleQueueEmptyTimeout() {}
    private void handleTransferTimeout() {}
    private void handleStampedLockFailure() {}
    private void handleCuratorLockFailure() {}
    private void handleRedisLockFailure() {}
    private void handleHazelcastLockFailure() {}
    private void handlePoolTimeout() {}
    private void handleZkTimeout() {}

    // Mock class for examples
    private static class StringPoolableObjectFactory implements org.apache.commons.pool2.PooledObjectFactory<String> {
        @Override
        public org.apache.commons.pool2.PooledObject<String> makeObject() {
            return new org.apache.commons.pool2.impl.DefaultPooledObject<>("pooled-string");
        }

        @Override
        public void destroyObject(org.apache.commons.pool2.PooledObject<String> p) {}

        @Override
        public boolean validateObject(org.apache.commons.pool2.PooledObject<String> p) {
            return true;
        }

        @Override
        public void activateObject(org.apache.commons.pool2.PooledObject<String> p) {}

        @Override
        public void passivateObject(org.apache.commons.pool2.PooledObject<String> p) {}
    }
}
// {/fact}