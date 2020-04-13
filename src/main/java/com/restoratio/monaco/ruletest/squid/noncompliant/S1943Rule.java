package com.restoratio.monaco.ruletest.squid.noncompliant;

import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import org.apache.commons.io.IOUtils;


public class S1943Rule {

    public void anIfMethod(InputStream a, Writer b) throws IOException {
        IOUtils.copy(a, b);
    }

}
