package com.restoratio.monaco.ruletest.findbugs.compliant;

import com.restoratio.brp.date_check.DateFormat;
import com.restoratio.brp.date_check.SimpleDateFormat;

public class RuleStaticSimpleDateFormatInstanceLibraryClass {

    /**
     * All fields below will be reported as errors. CodeGraph doesn't contain any
     * info about types from libraries - both 'com.restoratio.brp.date_check.DateFormat'
     * and 'java.text.DateFormat' will became 'DateFormat' in CG.
     */
    public static final DateFormat PRV_ST_FI_LOCAL_DATE_FORMAT = new SimpleDateFormat();

    protected static final DateFormat PRO_ST_FI_LOCAL_DATE_FORMAT = new SimpleDateFormat();

    public static final SimpleDateFormat PRV_ST_FI_LOCAL_SIMPLE_DATE_FORMAT = new SimpleDateFormat();

    protected static final SimpleDateFormat PRO_ST_FI_LOCAL_SIMPLE_DATE_FORMAT = new SimpleDateFormat();
}
