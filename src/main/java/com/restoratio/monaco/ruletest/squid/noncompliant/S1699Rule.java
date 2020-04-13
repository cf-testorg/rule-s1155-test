package com.restoratio.monaco.ruletest.squid.noncompliant;

public class S1699Rule {

    public S1699Rule() {
        doSomething();  // Noncompliant
    }

    public void doSomething() {  // not final; can be overridden
    }

}
