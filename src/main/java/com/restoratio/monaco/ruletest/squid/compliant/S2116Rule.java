package com.restoratio.monaco.ruletest.squid.compliant;

import java.util.Arrays;

public class S2116Rule {

    Object[] arrayObject = new Object[10];

    public static void main(String[] args) {
        String argStr = Arrays.toString(args);
        int argHash = Arrays.hashCode(args);
    }

    public void caseTwo() {
        String argStr = Arrays.toString(arrayObject);
        int argHash = Arrays.hashCode(arrayObject);
    }

    public void caseThree() {
        Object[] methodArray = new Object[10];
        String argStr = Arrays.toString(methodArray);
        int argHash = Arrays.hashCode(methodArray);
    }
}
