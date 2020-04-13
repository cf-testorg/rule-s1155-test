package com.restoratio.monaco.ruletest.squid.compliant;

import static org.apache.coyote.http11.Constants.a;

import java.io.IOException;

public class S1193Rule {

    @Override
    protected void finalize() throws Throwable { //compliant. Is protected
        try {
            byte b = 1;
            if (a > b) {
                throw new IOException();
            }
            throw new NullPointerException();
        } catch (IOException e) { /* ... */ }                // Compliant
        catch (
                NullPointerException e)

        { /* ... */ }       // Compliant
    }

    public String finalize(String method) { //Should not be detected.
        return "";
    }
}
