package com.restoratio.monaco.ruletest.internal.noncompliant;

import com.restoratio.monaco.ruletest.helpers.Cache;

public class NullCheckOnCache {

    public void testCacheCase(){

        Cache c = new Cache();

        System.out.println(c.getId());
        System.out.println(c.getName());

    }

}
