package com.restoratio.monaco.ruletest.squid.noncompliant;

public class S2116Rule {

    Object[] arrayObject = new Object[10];

    public static void main(String[] args) {
        String argStr = args.toString(); // Noncompliant
        int argHash = args.hashCode(); // Noncompliant
    }

    public void caseTwo() {
        String argStr = arrayObject.toString();
        int argHash = arrayObject.hashCode();
    }

    public void caseThree() {
        Object[] methodArray = new Object[10];
        String argStr = methodArray.toString();
        int argHash = methodArray.hashCode();
    }
}
