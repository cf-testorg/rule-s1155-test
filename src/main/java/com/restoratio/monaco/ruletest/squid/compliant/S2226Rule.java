package com.restoratio.monaco.ruletest.squid.compliant;

import javax.servlet.http.HttpServlet;

public class S2226Rule extends HttpServlet {

    /**
     *
     */
    private static final long serialVersionUID = 1L;
    private static String userName;

    public synchronized void testRule() {
        userName = "";
        System.out.println(userName);
    }

    public void testRule2() {
        System.out.println(userName);
    }

}
