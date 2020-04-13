package com.restoratio.monaco.ruletest.squid.noncompliant;

import java.util.Random;
import com.restoratio.monaco.ruletest.helpers.squid.MyRandom;

public class S2245Rule {

    private static final Random myGenerator = new Random(System.currentTimeMillis());
    private static final Random rnd = new Random();

    private Random r = new java.util.Random();
    private Random r2 = new Random(12);

    private final Random myRandom = new MyRandom();

    public int something() {
        return (int) Math.random();
    }

}
