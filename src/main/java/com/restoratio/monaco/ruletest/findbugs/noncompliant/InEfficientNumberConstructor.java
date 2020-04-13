package com.restoratio.monaco.ruletest.findbugs.noncompliant;

import java.util.List;

public class InEfficientNumberConstructor {

    private static long COUNT = 5;

    public void testRule1() {
        Integer numberInt = new Integer(127); // CASE A
        Long numberLong = new Long(-128); // CASE A
    }

    public void testRule2() {
        Integer numberInt = new Integer(126); // CASE A
        Long numberLong = new Long(-127); // CASE A
    }

    public void testRule3() {
        int numberIntPrim = 128;
        Integer numberInt = new Integer(numberIntPrim); //
        long numberLongPrim = -129;
        Long numberLong = new Long(numberLongPrim); //
    }

    public Integer testRule4() {
        return new Integer(0); // CASE A
    }

    public String testRule5(int myInt) {
        return new Integer(myInt).toString(); //
    }

    public int testRule6(String myString) {
        return new Integer(myString).intValue(); //
    }

    public Integer testRule7(String myString) {
        return new Integer(myString); //
    }

    public void testRule8(){
        Integer numberInt2 = new Integer(128);// CASE A
        Long numberLong2 = new Long(-129);// CASE A
    }

    public void testRule9(List list) {
        list.add(new Long(++COUNT)); //
    }

}
