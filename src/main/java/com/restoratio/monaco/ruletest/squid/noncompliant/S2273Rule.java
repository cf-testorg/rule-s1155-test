package com.restoratio.monaco.ruletest.squid.noncompliant;

public class S2273Rule {

    private Object obj;

    private void removeElement() throws InterruptedException {

        while (!suitableCondition()) {
            obj.wait();
        }
        // Perform removal
    }

    private boolean suitableCondition() {
        return true;
    }
}