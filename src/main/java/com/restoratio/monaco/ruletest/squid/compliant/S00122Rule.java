package com.restoratio.monaco.ruletest.squid.compliant;

public final class S00122Rule {

    public void doSomething() {
        boolean someCondition = true;
        if (someCondition) {
            doSomething();
        }
    }
}

