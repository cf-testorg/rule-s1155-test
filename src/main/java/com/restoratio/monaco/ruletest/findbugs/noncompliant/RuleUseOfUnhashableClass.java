package com.restoratio.monaco.ruletest.findbugs.noncompliant;

import java.util.HashSet;
import java.util.Set;

public class RuleUseOfUnhashableClass {


    private String name;
    private String address;

    public RuleUseOfUnhashableClass() {
        this.name = "TestName";
        this.address = "TestAddress";
    }

    public void testRule() {
        Set<RuleUseOfUnhashableClass> testSet = new HashSet<RuleUseOfUnhashableClass>();
        testSet.add(new RuleUseOfUnhashableClass());
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
        RuleUseOfUnhashableClass other = (RuleUseOfUnhashableClass) obj;
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


}
