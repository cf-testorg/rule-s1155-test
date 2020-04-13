package com.restoratio.monaco.ruletest.squid.compliant;

import java.util.Date;

public class S2133Rule {

    Date date2 = new Date();

    public void testGetClass() {
        Class c = Date.class;
    }

    public void test(Object obj) {
        if (Date.class == obj.getClass()) {

        }

        Date date1 = new Date();
        date1.setTime(1000L);
        date2.setTime(1000L);
        testMethodDate(date2);
        if(date1.getClass() == Date.class){
            testMethodDate(date1);
        }
    }

    public void test2(){
        if(date2.getClass() == Date.class){
            System.out.println(date2);
        }
    }

    public void testMethodDate(Date date){
        System.out.println(date);
    }
}
