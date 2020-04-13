package com.restoratio.monaco.ruletest.findbugs.compliant;

public class LazyInitUpdateStatic {

    static String[] weekends;

    //Test case 1
    public static synchronized String[] getWeekends() {
        if (weekends == null) {
            weekends = new String[2];
            weekends[0] = "Sunday";
            weekends[1] = "Saturday";
        }
        return weekends;
    }

    //Test case 2
    public static String[] getWeekends2() {
        Object b = new Object();
        synchronized (b) {
            if (weekends == null) {
                weekends = new String[2];
                weekends[0] = "Sunday";
                weekends[1] = "Saturday";
            }
        }
        return weekends;
    }

}
