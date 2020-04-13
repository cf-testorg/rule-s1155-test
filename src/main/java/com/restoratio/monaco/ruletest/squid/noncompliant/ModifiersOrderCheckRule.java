package com.restoratio.monaco.ruletest.squid.noncompliant;

import javax.validation.constraints.NotNull;

public class ModifiersOrderCheckRule {

    static public void main(String[] args) {
    }

    final public Integer case1() {
        return 1;
    }

    final static private String CASE2 = "Case2";

    synchronized protected static Integer case3() {
        return 2;
    }

    static public @NotNull Integer case4() {
        return 1;
    }

}
