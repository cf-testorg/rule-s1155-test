package com.restoratio.monaco.ruletest.findbugs.noncompliant;

public class RuleInfiniteRecursiveLoop {
    private Integer age;
    //Test case 1
    void testLoop(String b) {
        testLoop("dfdsfsd");
    }

    // Test case 2
    void testLoop2(String b, int x) {
        if (x == 1) {
            testLoop2(b, x);
        } else {
            doNothing();
        }
    }

    // Test case 3
    void testLoop3(String b, int x) {
        do {
            testLoop3(b, x);
            x--;
        } while (x > 5);
    }

    //Test case 4
    void testLoop4(String b, int x) {
        switch (x) {
            case 1:
                testLoop4(b, x);
                break;
            case 2:
                doNothing();
                break;
        }
    }

    // Test case 5
    void testLoop5(String b) {
        for (int x = 0; x < 10; x++) {
            testLoop5(b);
        }
    }

    // Test case 6
    void testLoop6(String b, int x) {
        do {
            x--;
            testLoop6(b, x);
        } while (x > 5);
    }
    // Test case 7
    void testLoop7() {
        switch (age) {
            case 1:
                testLoop7();
                break;
            case 2:
                doNothing();
                break;
        }
    }
    void doNothing() {

    }

    public int compareTo(final RuleInfiniteRecursiveLoop o) {
        return compareTo(o);
    }

}
