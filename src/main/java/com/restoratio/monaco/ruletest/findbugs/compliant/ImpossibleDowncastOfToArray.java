package com.restoratio.monaco.ruletest.findbugs.compliant;

import java.util.Arrays;
import java.util.Collection;

public class ImpossibleDowncastOfToArray {

    String[] getAsArray(Collection c) {
        return (String[])c.toArray(new String[c.size()]);
    }

    String[] getAsArray1(Collection c) {
        return (String[]) Arrays.asList(new String[] { "a" }).toArray();
    }
}
