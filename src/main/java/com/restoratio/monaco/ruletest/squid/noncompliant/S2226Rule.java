package com.restoratio.monaco.ruletest.squid.noncompliant;

import javax.servlet.http.HttpServlet;

public class S2226Rule extends HttpServlet {

    /**
     *
     */
    private static final long serialVersionUID = 1L;
    private String userName;

    public void testRule() {
        userName = "";
        System.out.println(userName);
    }

    public void testRule2() {
        System.out.println(userName);
    }

}
