package com.restoratio.monaco.ruletest.squid.noncompliant;

import java.util.Arrays;
import java.util.List;

public class S2446Rule {

    public synchronized void badCall() {
        notify();
    }

    public void willCheck() {
        S2446Rule local = new S2446Rule();
        local.notify();
        List<String> myList = Arrays.asList("ABC", "CDE");
        myList.notify();
    }
}
