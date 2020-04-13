package com.restoratio.monaco.ruletest.findbugs.noncompliant;

public class RuleInfiniteLoop {

    // Test case 1
    public static int test1(int n) {
        int i = 0;
        while (n >= 10) {
            i++;
        }
        return i;
    }

    // Test case 2
    public static int test2(int n1) {
        int n = n1;
        int i = 0;
        while (n >= 10) {
            i++;
        }
        return i;
    }


    // Test case 3
    public static void test3() {
        for (int x = 0; x > 10; ) {
            doNothing();
        }
    }

    // Test case 4
    public static int test4(int n) {
        int i = 0;
        while (n >= 10) {
            i = i + 1;
        }
        return i;
    }

    // Test case 5
    public static int test5(int n) {
        int i = 10;
        while (n >= 10) {
            i = i - 1;
        }
        return i;
    }


    private static void doNothing() {

    }

}
