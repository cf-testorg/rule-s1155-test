package com.restoratio.monaco.ruletest.findbugs.noncompliant;

import java.text.DateFormat;
import java.text.SimpleDateFormat;

public class RuleStaticSimpleDateFormatInstance {

    protected static final DateFormat PRO_ST_FI_DATE_FORMAT = SimpleDateFormat.getDateInstance();

    public static final DateFormat PUB_ST_FI_DATE_FORMAT = SimpleDateFormat.getDateInstance();

    protected static final SimpleDateFormat PRO_ST_FI_SIMPLE_DATE_FORMAT = null;

    public static final SimpleDateFormat PUB_ST_FI_SIMPLE_DATE_FORMAT = null;
}
