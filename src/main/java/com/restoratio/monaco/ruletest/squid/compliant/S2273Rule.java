package com.restoratio.monaco.ruletest.squid.compliant;

public class S2273Rule {

    private Object obj;

    private void removeElement() throws InterruptedException {
        synchronized (obj) {
            while (!suitableCondition()) {
                obj.wait();
            }
            // Perform removal
        }
    }

    private boolean suitableCondition() {
        return true;
    }
}