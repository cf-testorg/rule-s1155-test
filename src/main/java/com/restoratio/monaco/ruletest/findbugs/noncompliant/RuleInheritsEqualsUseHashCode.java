package com.restoratio.monaco.ruletest.findbugs.noncompliant;

public class RuleInheritsEqualsUseHashCode {

    public static abstract class AbstractEquals {

        @Override
        public boolean equals(Object o) {
            return o instanceof AbstractEquals;
        }
    }

    public static class InheritAbstractEquals extends AbstractEquals {

    }

    public static class InheritByIntermediate extends InheritAbstractEquals {

    }

    public static class InheritBySecondIntermediate extends InheritByIntermediate {

    }
}
