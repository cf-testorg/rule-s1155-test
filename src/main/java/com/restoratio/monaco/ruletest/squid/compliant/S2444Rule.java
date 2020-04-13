package com.restoratio.monaco.ruletest.squid.compliant;

public class S2444Rule {

    protected static Object syncObj = new Object();
    protected static Object instance;
    protected static volatile Object instance2;

    public static synchronized Object getInstance() {
        if (instance != null) {
            return instance;
        }

        instance = new Object(); //Compliant
        return instance;
    }

    public static Object getInstance2() {
        if (instance2 != null) {
            return instance2;
        }

        instance2 = new Object(); //Compliant
        return instance2;
    }

    public static Object getInstance3() {
        if (instance != null) {
            return instance;
        }

        synchronized (syncObj) {
            instance = new Object(); //Compliant
        }

        return instance;
    }

}
