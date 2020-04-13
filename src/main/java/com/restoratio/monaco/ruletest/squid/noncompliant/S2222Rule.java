package com.restoratio.monaco.ruletest.squid.noncompliant;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class S2222Rule {
    private Lock lock = new ReentrantLock();

		public void doSomething() {
				lock.lock();
				if (isInitialized()) {
						System.out.println("in doSomethingMethod");
						lock.unlock();//non-compliant
				}
		}

    public boolean doSomething2() throws InterruptedException {
        if(! lock.tryLock(2 , TimeUnit.MILLISECONDS ) ) {
            return false;
        }
        try {
            if (isInitialized()) {
                lock.unlock();
            }
        } catch (Exception e){

        }
        return true;
    }
		public boolean isInitialized() {
				return true;
		}
}
