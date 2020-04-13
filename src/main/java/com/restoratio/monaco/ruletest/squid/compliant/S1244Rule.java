package com.restoratio.monaco.ruletest.squid.compliant;

public class S1244Rule {

    public void testMethod() {
        float f = 0;
        double d = 0;
        if (f != f) { // Compliant; test for NaN value
            System.out.println("f is NaN");
        }

        if (f < 5 || f > 3) {

        }

        if (getFloatValue1() > getFloatValue2()) {

        }

        if (getFloatValue1() >= getFloatValue2()) {

        }

        if (getFloatValue1() < getFloatValue2()) {

        }

        if (getFloatValue1() <= getFloatValue2()) {

        }
    }

    private float getFloatValue1() {
        return 1.0f;
    }

    private float getFloatValue2() {
        return 1.0f;
    }
}
