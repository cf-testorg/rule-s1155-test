package com.restoratio.monaco.ruletest.findbugs.compliant;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class RuleEqualAlwaysFalse {

    private String name;
    private String address;

    public void testRuleWithSet() {
        Set<RuleEqualAlwaysFalse> testSet = new HashSet<>();
        testSet.add(new RuleEqualAlwaysFalse());
    }

    public void testRuleWithMap() {
        Map<String, RuleEqualAlwaysFalse> testMap = new HashMap<>();
        testMap.put("test", new RuleEqualAlwaysFalse());
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        RuleEqualAlwaysFalse other = (RuleEqualAlwaysFalse) obj;
        if (address == null) {
            if (other.address != null) {
                return false;
            }
        } else if (!address.equals(other.address)) {
            return false;
        }
        if (name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((address == null) ? 0 : address.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        return result;
    }
}
