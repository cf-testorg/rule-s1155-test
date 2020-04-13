package com.restoratio.monaco.ruletest.squid.noncompliant;

public class ObjectFinalizeCheckRule {

    public void dispose() throws Throwable {
        this.finalize();                       // Noncompliant
    }

}
