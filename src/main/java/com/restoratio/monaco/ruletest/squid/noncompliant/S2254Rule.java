package com.restoratio.monaco.ruletest.squid.noncompliant;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class S2254Rule extends HttpServlet {

    private HttpServletRequest fieldRequest;

    public void doGet(HttpServletRequest request,
                      HttpServletResponse response)
            throws ServletException, IOException {

        System.out.println(request.getRequestedSessionId());

    }

    public void testField(){
        System.out.println(fieldRequest.getRequestedSessionId());
    }

    public void testLocalVariable(){
        HttpServletRequest localVariable = fieldRequest;
        System.out.println(localVariable.getRequestedSessionId());
    }

}
