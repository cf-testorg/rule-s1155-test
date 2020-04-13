package com.restoratio.monaco.ruletest.findbugs.noncompliant;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class InconsistentSynchronization {
    private List<String> names;

    public void scan() {
        if (names == null) {
            synchronized (this) {
                names = new ArrayList<>();
                names.add(UUID.randomUUID().toString());
            }
        }
    }

    public List<String> getNames() {
        return names;
    }
}
