package com.restoratio.monaco.ruletest.squid.compliant;

import java.util.Date;

public class S2184Rule {

    long seconds = 2147483;

    float twoThirdsFloat = 2f / 3; // 2 promoted to float. Yields 0.6666667
    float multFloat = 2f * 3;
    double twoThirdsDouble = 2d / 3;
    double multiDouble = 2d * 3;
    long millisInYear = 1_000L * 3_600 * 24 * 365; // 1000 promoted to long. Yields 31_536_000_000
    int millisInYearInt = 1_000 * 3_600 * 24;
    long bigNum = Integer.MAX_VALUE + 2L; // 2 promoted to long. Yields 2_147_483_649
    long bigNegNum = Integer.MIN_VALUE - 1L; // Yields -2_147_483_649
    Date myDate = new Date(seconds * 1_000L);
    int intNum = 1000;
    long intNum2 = intNum + 2L;

    float twoThirds2Float = (float) 2 / 3; // 2 cast to float
    float multFloat2 = (float) 2 * 3;
    double twoThirdsDouble2 = (double) 2 / 3; // Noncompliant; int division. Yields 0.0
    double multiDouble2 = (double) 2 * 3;
    long millisInYear2 = (long) 1_000 * 3_600 * 24 * 365; // 1_000 cast to long
    long bigNum2 = (long) Integer.MAX_VALUE + 2;
    long bigNegNum2 = (long) Integer.MIN_VALUE - 1;
    Date myDate2 = new Date((long) seconds * 1_000);

    long testCast = (long)(60*1000 + 1);

    double testCast2 = getDoubleValue() * 1000;

    public long compute(int factor) {
        return factor * 10_000L;
    }

    public float compute2(long factor) {
        return factor / 123f;
    }

    public long compute(long factor) {
        return factor * 10_000;
    }

    public float compute2(float factor) {
        return factor / 123; //CASE B
    }

    public double compute3(double factor) {
        return factor / 123; //CASE B
    }

    public long compute4(){
        return System.currentTimeMillis() * 10_000;
    }

    public Double getDoubleValue(){
        return 1D;
    }

    public void testBoxing(){
        compute2(new Long(5*1000));
    }

}



