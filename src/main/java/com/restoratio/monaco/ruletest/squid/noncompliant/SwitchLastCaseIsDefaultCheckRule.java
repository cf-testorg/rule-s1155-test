package com.restoratio.monaco.ruletest.squid.noncompliant;

public class SwitchLastCaseIsDefaultCheckRule {

    public enum Day {
        FRIDAY, SATURDAY, SUNDAY, MONDAY
    }

    public void testSwitch(Integer param) {
        switch (param) {  //missing default clause
            case 0:
                doSomething();
                break;
            case 1:
                doSomethingElse(1);
                break;
            case 2:
                doSomethingElse(2);
                break;
        }

        switch (param) {
            default: // default clause should be the last one
                error();
                break;
            case 0:
                doSomething();
                break;
            case 1:
                doSomethingElse(1);
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
