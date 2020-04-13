package com.restoratio.monaco.ruletest.squid.compliant;

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
        if (this.getClass() == obj.getClass()) {
            return ripe.equals(((S2162Rule)obj).getRipe());
        }
        return false;
    }

    public Season getRipe() {
        return ripe;
    }
}
