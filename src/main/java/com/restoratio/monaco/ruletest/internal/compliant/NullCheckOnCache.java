package com.restoratio.monaco.ruletest.internal.compliant;

import com.restoratio.monaco.ruletest.helpers.Cache;

public class NullCheckOnCache {


    public void testCacheCase() {

        Cache c = new Cache();

        System.out.println(c.getId() != null ? c.getId() : null);
        System.out.println(c.getName() != null ? c.getName() : null);

        if (c.getId() != null) {
            System.out.println(c.getId());
        }

        if (c.getName() != null) {
            System.out.println(c.getName());
        }

    }

}
