package com.restoratio.monaco.ruletest.squid.compliant;

import java.text.SimpleDateFormat;
import java.util.Calendar;

public class S2885Rule {

    private SimpleDateFormat format = new SimpleDateFormat("HH-mm-ss"); // Noncompliant
    private Calendar calendar = Calendar.getInstance(); // Noncompliant

}
