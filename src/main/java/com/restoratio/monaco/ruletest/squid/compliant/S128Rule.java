package com.restoratio.monaco.ruletest.squid.compliant;

public final class S128Rule {

    public void check(int i) {
        switch(i) {
            case 0:
                if (System.currentTimeMillis() > 10) {
                    return;
                } else {
                    break;
                }
            case 2:
                System.out.println("abc");
                return;
            case 3:
            case 4:
                break;
            default:
        }
    }

    public void switchWithIf(String a) {
        switch(a) {
            case "x":
                if (a.length() > 5) {
                    if (toString().toLowerCase().equals("b")) {
                        return;
                    } else {
                        break;
                    }
                } else {
                    throw new IllegalStateException("x");
                }
            case "y":
                switch (a) {
                    case "b":
                        return;
                    default:
                }
                break;
            default:
                return;
        }
    }

    private TestA check2(byte b, char c) {
        int myVariable = 0;
        switch (myVariable) {
            case 12: // Compliant
                try {
                    return new TestA(true);
                } catch (Exception e) {
                    throw new RuntimeException("Wrapping", e);
                }
            case 9: // Compliant
        }

        return new TestA(false);
    }


    private void check3(int myVariable) {
        for (int i = 0; i < 1; i++) {
            switch (myVariable) {
                case 0: // Compliant
                    continue; // belongs to for loop
                case 1:
                    break;
            }
        }
    }

    class TestA{

        boolean bool;

        TestA(boolean bool){
            this.bool = bool;
        }
    }

}
