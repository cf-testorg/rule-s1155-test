package com.restoratio.monaco.ruletest.squid.compliant;

public class S2236Rule {

    public void testThreadWait() throws InterruptedException {
        Thread myThread = new Thread();
        Integer x = 1;
        synchronized (new Object()) {
            while (x != 2) {
                x++;
                x.wait(2000);
            }
        }
        myThread.start();
    }

}
