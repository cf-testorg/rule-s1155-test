package com.restoratio.monaco.ruletest.findbugs.compliant;

import com.restoratio.monaco.ruletest.helpers.findbugs.DateFormat;
import com.restoratio.monaco.ruletest.helpers.findbugs.SimpleDateFormat;

public class RuleStaticSimpleDateFormatInstanceLocalClass {

    public static final DateFormat PRV_ST_FI_LOCAL_DATE_FORMAT = new SimpleDateFormat();

    protected static final DateFormat PRO_ST_FI_LOCAL_DATE_FORMAT = new SimpleDateFormat();

    public static final SimpleDateFormat PRV_ST_FI_LOCAL_SIMPLE_DATE_FORMAT = new SimpleDateFormat();

    protected static final SimpleDateFormat PRO_ST_FI_LOCAL_SIMPLE_DATE_FORMAT = new SimpleDateFormat();

}
