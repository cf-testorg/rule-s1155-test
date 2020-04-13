package com.restoratio.monaco.ruletest.squid.compliant;

public class S1764Rule {

    public void testSameExpression() {
        int a = 1;
        int b = 2;
        int c = 3;
        if (a == c) { // always true
            doSomething();
        }
        if (a != c) { // always false
            doSomething();
        }
        if (a == c && a == b) { // if the first one is true, the second one is too
            doSomething();
        }
        if (a == c || a == b) { // if the first one is true, the second one is too
            doSomething();
        }

        int j = 6 / 2; // always 3
        int k = 6 - 5; // always 1

        int bitwise = 1 << 1; // Compliant

        doSomething(j);
        doSomething(k);

        float f = 1f;
        if (f != f) { //test for NaN value
            System.out.println("f is NaN");
        }
    }

    private void doSomething() {
        throw new UnsupportedOperationException();
    }

    private void doSomething(int i) {
        throw new UnsupportedOperationException(Integer.toString(i));
    }

}
