package com.restoratio.monaco.ruletest.findbugs.noncompliant;

public class RuleEqualAlwaysFalse {

    public static class WithAnnotation {
        @Override
        public boolean equals(Object obj) {
            return false;
        }

        @Override
        public int hashCode() {
            return 0;
        }
    }

    public static class WithOutAnnotation {

        @Override
        public boolean equals(Object obj) {
            return false;
        }

        @Override
        public int hashCode() {
            return 0;
        }
    }
}
