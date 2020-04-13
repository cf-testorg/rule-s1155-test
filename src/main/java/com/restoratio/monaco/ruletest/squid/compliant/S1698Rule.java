package com.restoratio.monaco.ruletest.squid.compliant;

public class S1698Rule {

    public void test() {

        String test = "test";
        if (test.equals("test")) {
        }

        if (!test.equals("")) {
        }

        WithAnnotation with1 = new WithAnnotation();
        WithAnnotation with2 = new WithAnnotation();
        if (with1.equals(with2)) {
        }

        WithOutAnnotation without1 = new WithOutAnnotation();
        WithOutAnnotation without2 = new WithOutAnnotation();
        if (!without1.equals(without2)) {
        }

        WithOutAnnotationChild wc1 = new WithOutAnnotationChild();
        WithOutAnnotationChild wc2 = new WithOutAnnotationChild();
        if (wc1.equals(wc2)) {
        }

        WithOutAnnotationGrandChild wgc1 = new WithOutAnnotationGrandChild();
        WithOutAnnotationGrandChild wgc2 = new WithOutAnnotationGrandChild();
        if (!wc1.equals(wc2)) {
        }
    }

    public static class WithAnnotation {
        @Override
        public boolean equals(Object obj) {
            return false;
        }

        @Override
        public int hashCode() {
            return 0;
        }

        public void test(WithAnnotation w1) {
            if (this.equals(w1)) {
            }
        }
    }

    public static class WithOutAnnotation {

        public boolean equals(Object obj) {
            return false;
        }

        public int hashCode() {
            return 0;
        }
    }

    public static class WithOutAnnotationChild extends WithOutAnnotation {

    }

    public static class WithOutAnnotationGrandChild extends WithOutAnnotationChild {

    }
}
