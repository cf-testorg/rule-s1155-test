package com.restoratio.monaco.ruletest.squid.compliant;

public class S1143Rule {

    public static void main(String[] args) {
        try {
            doSomethingWhichThrowsException();
            System.out.println("OK");
        } catch (RuntimeException e) {
            System.out.println("ERROR");
        }
    }


    public static void doSomethingWhichThrowsException() {
        try {
            throw new RuntimeException();
        } finally {
            System.out.println("FINALLY OK");
        }
    }


    public static void case3() {
        int x = 0;
        try {
            x++;
            throw new RuntimeException();
        } finally {
            while (x < 10) {
                x++;
                if (x == 8) {
                    continue; // Compliant
                }
            }
        }
    }

    public static void case4() {
        int x = 0;
        try {
            x++;
            throw new RuntimeException();
        } finally {
            while (x < 10) {
                if (x == 8) {
                    break;// Compliant
                }
            }
        }
    }

    public static void case5() {
        int x = 0;
        try {
            x++;
            throw new RuntimeException();
        } finally {
            do {
                if (x == 8) {
                    break;// Compliant
                }
            } while (x < 10);
        }
    }

    public static void case6() {
        int x = 0;
        try {
            x++;
            throw new RuntimeException();
        } finally {
            for (int y = 0; y < 10; y++) {
                if (y == 8) {
                    break;// Compliant
                }
            }
        }
    }

    public static void case7() {
        int x = 0;
        try {
            x++;
            throw new RuntimeException();
        } finally {
            switch (x) {
                case 1:
                    x = 1;
                    break;
                case 2:
                    x = 2;
                    break;
                default:
                    x = 3;
            }
        }
    }
}



