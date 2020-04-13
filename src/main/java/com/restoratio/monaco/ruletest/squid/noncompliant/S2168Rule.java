package com.restoratio.monaco.ruletest.squid.noncompliant;

public final class S2168Rule {

    private static Resource resource;

    public static Resource getInstance() {
        if (resource == null) {
            synchronized (S2168Rule.class) {
                if (resource == null)
                    resource = new Resource();
            }
        }
        return resource;
    }

    static class Resource {

    }

}
