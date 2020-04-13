package com.restoratio.monaco.ruletest.squid.noncompliant;

import com.restoratio.monaco.ruletest.helpers.Food;
import com.restoratio.monaco.ruletest.helpers.Season;

public class S2162Rule extends Food {

    private Season ripe;

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (S2162Rule.class == obj.getClass()) { // Noncompliant; broken for child classes
            return ripe.equals(((S2162Rule) obj).getRipe());
        }
        if (obj instanceof S2162Rule) {  // Noncompliant; broken for child classes
            return ripe.equals(((S2162Rule) obj).getRipe());
        } else if (obj instanceof Season) { // Noncompliant; symmetry broken for Season class
            // ...
        }
        return false;
    }
    public Season getRipe() {
        return ripe;
    }
}
