package com.restoratio.monaco.ruletest.squid.noncompliant;

import com.restoratio.monaco.ruletest.squid.compliant.MyLock;

public class S2222Rule2 extends MyLock {

    public void doSomething() {
        super.lock();
        if (isInitialized()) {
            System.out.println("in doSomethingMethod");
            super.unlock();//non-compliant
        }
    }

    public boolean isInitialized() {
        return true;
    }

}
