package com.restoratio.monaco.ruletest.squid.noncompliant;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

public class S2112Rule {

    public void checkUrl(URL url) throws MalformedURLException {
        Set<URL> sites = new HashSet<URL>();  // Noncompliant

        URL homepage = new URL("http://sonarsource.com");  // Compliant
        if (homepage.equals(url)) { // Noncompliant
            // ...
        }
        if (homepage.hashCode() > 0){ // Noncompliant
            // ...
        }
    }

}
