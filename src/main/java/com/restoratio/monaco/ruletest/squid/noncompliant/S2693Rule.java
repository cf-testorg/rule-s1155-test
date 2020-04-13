package com.restoratio.monaco.ruletest.squid.noncompliant;

public class S2693Rule extends Thread {

    public S2693Rule()
    {
        new Thread( this ).start();
    }
}
