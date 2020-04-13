package com.restoratio.monaco.ruletest.squid.compliant;

import java.io.IOException;
import java.io.Serializable;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class S2441aRule implements SerializableTest{
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        HttpSession session = request.getSession();
        session.setAttribute("address", new S2441aRule());  // Compliant; S2441Rule is serializable
    }
}
