package com.restoratio.monaco.ruletest.squid.compliant;

import java.util.Date;

public class SwitchLastCaseIsDefaultCheckRule {

    public enum Day {
        SATURDAY, SUNDAY, MONDAY
    }

    public void testSwitch(Integer param) {
        switch (param) {
            case 0:
                doSomething();
                break;
            case 1:
                doSomethingElse(1);
                break;
            default:
                error();
                break;
        }
    }

    public void testSwitchEnum(Day day) {
        switch(day) {
            case SATURDAY:
                doSomething();
                break;
            case SUNDAY:
                doSomethingElse(1);
                break;
            case MONDAY:
                doSomethingElse(2);
                break;
        }
    }

    public void doSomething() {
        System.out.println("doSomething");
    }

    public void doSomethingElse(int x) {
        System.out.println("doSomethingElse()");
    }

    public void error() {
        System.out.println("error()");
    }
}
