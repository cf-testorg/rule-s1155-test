package com.restoratio.monaco.ruletest.squid.noncompliant;

public final class S128Rule {

    private char next() {
        return 'c';
    }

    public void sampleSwitch(int i) {
        switch(i) {
            case 0:
                new IllegalArgumentException();
            case 1:
                return;
            default:
                break;
        }
    }

    public void switchInSwitch(int check, int subCheck) {
        switch (check) {
            case 0:
                switch (subCheck) {
                    case 0:
                        break;
                    case 1:
                        System.gc();
                    case 2:
                        break;
                    default:
                        break;
                }
            case 1:
                break;
            case 2:
                switch (subCheck) {
                    case 0:
                        return;
                    case 1:
                        return;
                    default:
                        return;
                }
            default:
                return;
        }
    }

    public char doSomething() {
        char q;
        char c = next();

        switch(c) {
            case ';':
                q = c;
                for (;;) {
                    c = next();
                    if (c == 0) {
                        throw new IllegalStateException("test");
                    }
                    if (q == c) {
                        return c;
                    }
                }
            case '!':
                if (Character.isLowerCase(c))
                    return c;
            default:
                return c;
        }
    }

}
