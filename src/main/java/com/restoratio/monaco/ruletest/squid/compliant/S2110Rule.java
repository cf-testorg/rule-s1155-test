package com.restoratio.monaco.ruletest.squid.compliant;

import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

public class S2110Rule {

    // Test case 1
    public void testDate1() {
        Date d = new Date();
        d.setDate(28);
        d.setYear(2014);
        d.setMonth(11);
        d.setHours(23);
        d.setMinutes(59);
        d.setSeconds(59);

        Calendar c = new GregorianCalendar(2014, 11, 28);
        if (c.get(Calendar.MONTH) == 11) {
            doNothing();
        }

        if (c.get(Calendar.DAY_OF_MONTH) == 28) {
            doNothing();
        }

        if (c.get(Calendar.HOUR_OF_DAY) == 23) {
            doNothing();
        }

        if (c.get(Calendar.MINUTE) == 59) {
            doNothing();
        }

        if (c.get(Calendar.SECOND) == 59) {
            doNothing();
        }

        if (c.get(Calendar.HOUR) == 11) {
            doNothing();
        }

        Date dateMin = new Date(0);
        Date dateMax = new Date(9223372036854775807L);
    }

    // Test case 2
    public void testDate2() {
        java.sql.Date dateSql = new java.sql.Date(2020, 11, 2);
        dateSql.setYear(2021);
        dateSql.setMonth(11);
        dateSql.setDate(28);
        dateSql.setHours(23);
        dateSql.setMinutes(59);
        dateSql.setSeconds(59);

    }

    public void doNothing() {

    }

}
