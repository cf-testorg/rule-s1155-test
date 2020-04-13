package com.restoratio.monaco.ruletest.findbugs.compliant;

public class InEfficientNumberConstructor {

    public void testRule1() {
        Integer numberInt = Integer.valueOf(127);
        Long numberLong = Long.valueOf(-128);
    }

    public String testRule2(int myInt) {
        return ((Integer) myInt).toString();
    }

    public String testRule3(int myInt) {
        return Integer.toString(myInt);
    }

    public int testRule4(String myString) {
        return Integer.parseInt(myString);
    }

    public Integer testRule5(String myString) {
        return Integer.valueOf(myString);
    }

    public void testRule6() {
        int numberIntPrim = 127;
        Integer numberInt = Integer.valueOf(numberIntPrim);
        long numberLongPrim = -128;
        Long numberLong = Long.valueOf(numberLongPrim);
    }

}
