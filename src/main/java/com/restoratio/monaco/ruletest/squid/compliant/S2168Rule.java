package com.restoratio.monaco.ruletest.squid.compliant;

public final class S2168Rule {
    private static Resource resource;

    public synchronized static Resource getInstance() {
        if (resource == null)
            resource = new Resource();
        return resource;
    }

    static class Resource {
    }
}
