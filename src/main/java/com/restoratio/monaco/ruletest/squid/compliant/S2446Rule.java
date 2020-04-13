package com.restoratio.monaco.ruletest.squid.compliant;

import java.util.Arrays;
import java.util.List;

public class S2446Rule {

    public synchronized void makeSomething() {
        notifyAll();
    }

    public void somethingElse() {
        S2446Rule rule = new S2446Rule();
        rule.notifyAll();
        List<String> myList = Arrays.asList("ABC", "CDE");
        myList.notifyAll();
    }
}
