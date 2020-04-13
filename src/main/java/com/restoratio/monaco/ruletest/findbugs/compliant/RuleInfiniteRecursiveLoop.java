package com.restoratio.monaco.ruletest.findbugs.compliant;

import java.util.Arrays;
import java.util.List;

public class RuleInfiniteRecursiveLoop extends RuleInfiniteRecursiveLoopCompare{

    private String name;
    private Integer age;

    // Test case 1
    void testLoop(String b, int x) {
        if (x < 10) {
            testLoop("dfdsfsd", x++);
        }
    }

    // Test case 2
    void testLoop2(String b, int x) {
        testLoop3(b);
    }

    // Test case 3
    void testLoop3(String b) {
        testLoop2(b, 1);
    }

    // Test case 4
    void testLoop4(String b, int x) {
        switch (x) {
            case 1:
                x = x + 1;
                testLoop4(b, x);
                break;
            case 2:
                x = x + 2;
                doNothing();
                break;
        }
    }

    // Test case 5
    void testLoop5(String b, int x) {
        List<String> testString = Arrays.asList("One", "Two", "Three");
        for (String value : testString) {
            testLoop5(value, x);
        }
    }

    // Test case 6
    void testLoop6(String b, int x) {
        while (x > 5) {
            testLoop6(b, x);
            x++;
        }
    }

    // Test case 7
    void testLoop7(String b, int x) {
        testLoop7(b);
    }

    void testLoop7(String b) {
        doNothing();
    }


    void doNothing() {

    }

    void checkCatchInterruptedException(){
        while(!Thread.interrupted()) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                checkCatchInterruptedException();
            }
        }
    }

    boolean h(boolean in) {
        if (in) {
            h(!in);
        }
        return false;
    }

    @Override
    public int compareTo(RuleInfiniteRecursiveLoopCompare s) {
        return super.compareTo(s);
    }

    void methodB() {
        super.methodB();
    }

}
class RuleInfiniteRecursiveLoopCompare implements Comparable<RuleInfiniteRecursiveLoopCompare> {


    @Override
    public int compareTo(RuleInfiniteRecursiveLoopCompare o) {
        return 0;
    }

    void methodB() {
    }
}