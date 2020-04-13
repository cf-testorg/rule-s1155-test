package com.restoratio.monaco.ruletest.findbugs.noncompliant;

interface Colorable {

    void setColor(int color);
}

public class ImpossibleCast {

    public static void main(String[] args) {
        Point[] pa = new Point[100];

        // The following line will throw a ClassCastException:
        ColoredPoint[] cpa = (ColoredPoint[]) pa;
        System.out.println(cpa[0]);

        int[] shortvec = new int[2];
        Object o = shortvec;

        // The following line will throw a ClassCastException:
        Colorable c = (Colorable) o;
        c.setColor(0);
    }
}

class Point {

    int x, y;
}

class ColoredPoint extends Point implements Colorable {

    int color;

    public void setColor(int color) {
        this.color = color;
    }
}