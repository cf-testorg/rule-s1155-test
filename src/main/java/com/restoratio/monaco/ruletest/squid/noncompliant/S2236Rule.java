package com.restoratio.monaco.ruletest.squid.noncompliant;

public class S2236Rule {

    public void testThreadWait() throws InterruptedException {
        Thread myThread = new Thread();
        Integer x = 1;
        while (x != 2) {
            x++;
            myThread.wait(2000);
        }
    }

    public void testRunnable() throws Exception {
        MyRunnable runnable = new MyRunnable();
        Integer x = 1;
        while (x != 2) {
            x++;
            runnable.wait();
            runnable.wait(100);
            runnable.notify();
            runnable.notifyAll();
        }
    }

}
