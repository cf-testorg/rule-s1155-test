package com.restoratio.monaco.ruletest.squid.noncompliant;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class S2441Rule {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        HttpSession session = request.getSession();
        session.setAttribute("address", new S2441Rule());  // Noncompliant; S2441Rule isn't serializable
    }
}
