package com.restoratio.monaco.ruletest.squid.noncompliant;

import java.util.Date;

public class S2133Rule {

    Date varDate = new Date();

    public void testGetClass() {
        Date varDate2 = new Date();
        Class d = new Date().getClass();
        Class c = varDate.getClass();
        Class e = varDate2.getClass();
    }

}
