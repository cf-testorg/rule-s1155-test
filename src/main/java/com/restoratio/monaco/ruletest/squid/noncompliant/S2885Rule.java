package com.restoratio.monaco.ruletest.squid.noncompliant;

import java.text.SimpleDateFormat;
import java.util.Calendar;

public class S2885Rule {

    private static SimpleDateFormat format, teste = new SimpleDateFormat("HH-mm-ss"); // Noncompliant
    private static Calendar calendar = Calendar.getInstance(); // Noncompliant


}
