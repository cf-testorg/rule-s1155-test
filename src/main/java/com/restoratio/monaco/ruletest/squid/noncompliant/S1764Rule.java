package com.restoratio.monaco.ruletest.squid.noncompliant;

public class S1764Rule {

    public void testSameExpression() {
        int a = 1;
        int b = 2;
        if (a == a) { // always true
            doSomething();
        }
        if (a != a) { // always false
            doSomething();
        }
        if (a == b && a == b) { // if the first one is true, the second one is
            // too
            doSomething();
        }
        if (a == b && b == a) { // if the first one is true, the second one is
            // too
            doSomething();
        }
        if ((a == b) && (b == a)) { // Add extra useless parenthesis
            doSomething();
        }
        if (((a == b)) && ((b == a))) { // Add more extra useless parenthesis
            doSomething();
        }

        if (a == b || a == b) { // if the first one is true, the second one is
            // too
            doSomething();
        }

        int j = 5 / 5; // always 1
        int k = 5 - 5; // always 0

        int bitwise = a << a; // Noncompliant

        doSomething(j);
        doSomething(k);

        if (b != '5' && b != '5') {
        }

        String filename = "a file";
        if (filename.startsWith("file:/")
            || filename.startsWith("http://")
            || filename.startsWith("https://")
            || filename.startsWith("jar:")
            || filename.startsWith("wsjar:")
            || filename.startsWith("wsjar:")
            || filename.startsWith("vfszip:")) {
        }

    }

    private void doSomething() {
        throw new UnsupportedOperationException();
    }

    private void doSomething(int i) {
        throw new UnsupportedOperationException(Integer.toString(i));
    }

}
