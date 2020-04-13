package com.restoratio.monaco.ruletest.squid.compliant;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class S2222Rule {
    private Lock lock = new ReentrantLock();

    public void doSomething() {
        if (isInitialized()) {
            lock.lock();
            System.out.println("in doSomethingMethod");
            lock.unlock();
        }
    }

    public void anyMethod() {
        lock.lock();
        try {
            //perform task
        }finally {
            lock.unlock();
        }
    }
    public boolean m() throws InterruptedException {
        if(! lock.tryLock(2 , TimeUnit.MILLISECONDS ) ) {
            return false;
        }
        try {
            // ... method body
        } finally {
            lock.unlock();
        }
        return true;
    }

    public void anyMethod3() {
        if(lock.tryLock() ) {
            try {
                // ... method body
            } finally {
                lock.unlock();
            }
        }
    }
    public void doSomething2() {

        try {
            lock.lock();
            System.out.println("in doSomethingMethod");
        } catch (Throwable t) {
            System.err.println("Error in doSomethingMethod");
        } finally {
            lock.unlock();
        }

    }

    public void foo() {
        Lock lock = null;
        try {
            lock = getLock();
            lock.lock();
            try {
                doSomething();
            } finally {
                if (lock != null) {
                    lock.unlock();
                }
            }
        } catch (RuntimeException e) {
            doSomething();
        }
    }

    public void anyMethod2() {
        try {
            System.out.println("in anyMethod");
            lock.lock();
        }finally {
            lock.unlock();
        }
    }

    public Lock getLock(){
        return lock;
    }

    public boolean isInitialized() {
        return true;
    }


}
