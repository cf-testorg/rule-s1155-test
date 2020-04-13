package com.restoratio.monaco.ruletest.squid.noncompliant;


public class S1244Rule {

    public void testMethod() {

        float myNumber = (float) 3.146;
        float mySecondNumber = 3.146f;

        Float myFloatObj = 3.146f;
        double myDouble = 3.146;
        Double myDoubleObj = 3.146;
        if (myNumber == 3.146f) {
        }

        if (myFloatObj == 3.146f) {
        }

        if (myDouble == 3.146f) {
        }

        if (myDoubleObj == 3.146f) {
        }


        if (myNumber == 3.146f) {
        }

        if (myNumber != 3.146f) { //Noncompliant. Because of floating point imprecision, this will be true

        }

        if (myNumber == mySecondNumber) {
        }

        float f = 0;
        double d = 0;
        if (f != d) { // Noncompliant

        }

        if (getFloatValue1() == getFloatValue2()) {

        }

        if (getFloatValue1() != getFloatValue2()) {

        }


    }

    private float getFloatValue1() {
        return 1.0f;
    }

    private float getFloatValue2() {
        return 1.0f;
    }
}
