package com.restoratio.monaco.ruletest.squid.noncompliant;

import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

public class S2110Rule {

    // Test case 1
    public void testDate1() {
        Date d = new Date();
        d.setDate(50);
        d.setYear(2014);
        d.setMonth(12); // Noncompliant; rolls d into the next year
        d.setHours(50);
        d.setMinutes(90);
        d.setSeconds(70);

        Calendar c = new GregorianCalendar(2014, 12, 1); // Noncompliant - month
        Calendar calMth = new GregorianCalendar(2014, 11, 35); // Noncompliant - day of month
        Calendar calHr = new GregorianCalendar(2014, 11, 20, 24, 0); // Noncompliant - hour of day
        Calendar calMin = new GregorianCalendar(2014, 11, 20, 12, 90); // Noncompliant - minutes
        Calendar calSecs = new GregorianCalendar(2014, 11, 20, 12, 30, 90); // Noncompliant -

        // seconds

        if (c.get(Calendar.MONTH) == 12) { // Noncompliant; invalid comparison
            doNothing();
        }

        c.set(Calendar.MONTH, 12);

        if (c.get(Calendar.DAY_OF_MONTH) == 50) { // Noncompliant; invalid comparison
            doNothing();
        }

        c.set(Calendar.DAY_OF_MONTH, 50);

        if (c.get(Calendar.HOUR_OF_DAY) == 25) { // Noncompliant; invalid comparison
            doNothing();
        }

        c.set(Calendar.HOUR_OF_DAY, 25);

        if (c.get(Calendar.MINUTE) == 61) { // Noncompliant; invalid comparison
            doNothing();
        }

        c.set(Calendar.MINUTE, 61);

        if (c.get(Calendar.SECOND) == 100) { // Noncompliant; invalid comparison
            doNothing();
        }

        c.set(Calendar.SECOND, 100);

        if (c.get(Calendar.HOUR) == 50) { // Noncompliant; invalid comparison
            doNothing();
        }

        c.set(Calendar.MILLISECOND, 100000);

        c.set(Calendar.HOUR, 50);

        Date invalidDateMinus = new Date(-1L);

    }

    // Test case 2
    public void testDate2() {
        java.sql.Date dateSql = new java.sql.Date(2020, 12, 50);
        dateSql.setYear(2021);
        dateSql.setMonth(12);
        dateSql.setDate(50);
        dateSql.setHours(50);
        dateSql.setMinutes(90);
        dateSql.setSeconds(70);

    }

    public void doNothing() {

    }

}
