package com.restoratio.monaco.ruletest.squid.compliant;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class S2274Rule {

    private static final int TIMEOUT = 2000;
    Condition classCondition;

    public void waitTest() throws InterruptedException {
        Integer obj = 1;
        synchronized (new Object()) {
            while (obj != 2) {
                obj++;
                obj.wait(1000); // the thread can wakeup whereas the condition
                // is still false
            }

        }
    }

    public void waitAnotherOkTest() throws InterruptedException {
        Integer obj = 1;
        synchronized (new Object()) {
            do {
                obj++;
                obj.wait(1000);
            } while (obj != 2);
        }
    }

    public void testThreadWait_Case2() throws InterruptedException {
        Thread myThread = new Thread();
        Integer x = 1;
        synchronized (new Object()) {
            while (x != 2) {
                x++;
                x.wait(TIMEOUT);
            }
        }
        myThread.start();
    }

    public void testInsideForLoop() throws InterruptedException {
        Thread myThread = new Thread();
        Integer x = 1;
        synchronized (new Object()) {
            for (;;) {
                x++;
                x.wait(TIMEOUT);
                if(x>1000) break;
            }
        }
        myThread.start();
    }

    public void testUtilCondition() throws InterruptedException {
        Lock lock = new ReentrantLock();
        Condition notFull = lock.newCondition();
        int obj = 0;
        do {
            obj++;
            notFull.await(1,TimeUnit.MINUTES);
        } while (obj < 10);
    }

    public void testUtilClassCondition() throws InterruptedException {
        Lock lock = new ReentrantLock();
        classCondition = lock.newCondition();
        int obj = 0;
        do {
            obj++;
            classCondition.await(1,TimeUnit.MINUTES);
        } while (obj < 10);
    }

    public void testUtilCondition(Condition condition) throws InterruptedException {
        int obj = 0;
        do {
            obj++;
            condition.await(1,TimeUnit.MINUTES);
        } while (obj < 10);
    }

    public void testCountDownLatch() throws InterruptedException {
        CountDownLatch startSignal = new CountDownLatch(1);
        startSignal.await(1, TimeUnit.MINUTES);
    }

    public void testNonInheritedWait() {
        WaitTest wait = new WaitTest();
        wait.wait("None");
    }

    class WaitTest {

        public void wait(String param) {
            doNothing();
        }

        private void doNothing() {
            System.out.println("doNothing");
        }
    }

}
