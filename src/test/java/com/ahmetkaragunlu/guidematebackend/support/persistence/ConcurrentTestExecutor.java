package com.ahmetkaragunlu.guidematebackend.support.persistence;

import org.junit.jupiter.api.Assertions;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public final class ConcurrentTestExecutor {

    private ConcurrentTestExecutor() {
    }

    public static <T> List<T> run(Callable<T> first, Callable<T> second) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try {
            Future<T> firstFuture = executor.submit(gated(first, ready, start));
            Future<T> secondFuture = executor.submit(gated(second, ready, start));
            Assertions.assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            return Arrays.asList(
                    firstFuture.get(10, TimeUnit.SECONDS),
                    secondFuture.get(10, TimeUnit.SECONDS)
            );
        } finally {
            start.countDown();
            executor.shutdownNow();
        }
    }

    private static <T> Callable<T> gated(Callable<T> task, CountDownLatch ready, CountDownLatch start) {
        return () -> {
            ready.countDown();
            if (!start.await(5, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Concurrent test start timed out");
            }
            return task.call();
        };
    }
}
