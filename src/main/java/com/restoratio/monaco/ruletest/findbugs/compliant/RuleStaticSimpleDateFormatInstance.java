package com.restoratio.monaco.ruletest.findbugs.compliant;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

public class RuleStaticSimpleDateFormatInstance {

    private static final DateFormat PRV_ST_FI_DATE_FORMAT = SimpleDateFormat.getDateInstance();

    static final DateFormat ST_FI_DATE_FORMAT = SimpleDateFormat.getDateInstance();

    private static final SimpleDateFormat PRV_ST_FI_SIMPLE_DATE_FORMAT = null;

    static final SimpleDateFormat ST_FI_SIMPLE_DATE_FORMAT = null;

    protected final DateFormat PRO_FI_DATE_FORMAT = SimpleDateFormat.getDateInstance();

    public final DateFormat PUB_FI_DATE_FORMAT = SimpleDateFormat.getDateInstance();

    protected final SimpleDateFormat PRO_FI_SIMPLE_DATE_FORMAT = null;

    public final SimpleDateFormat PUB_FI_SIMPLE_DATE_FORMAT = null;

    public void insideMethod() {
        final DateFormat dataFormat = SimpleDateFormat.getDateInstance();
        final SimpleDateFormat simpleDateFormat = null;
        dataFormat.format(new Date());
    }

}
