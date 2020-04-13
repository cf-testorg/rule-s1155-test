package com.restoratio.monaco.ruletest.squid.noncompliant;

public class S1221Rule {

    public static final class WithPublicHashcodeMethod {
        public int hashcode() {
            return 0;
        }
    }

    public static final class WithPublicHashcodeMethodReturnVoid {
        public void hashcode() {
            System.out.println("void");
        }
    }

    public static final class WithPublicHashcodeMethodWithArgument {
        public int hashcode(Object o) {
            return System.identityHashCode(o);
        }
    }

    public static final class WithPrivateHashcodeMethod {
        private int hashcode() {
            return 0;
        }
    }

    public static final class WithProtectedHashcodeMethod {
        protected int hashcode() {
            return 0;
        }
    }

    public static final class WithDefaultHashcodeMethod {
        protected int hashcode() {
            return 0;
        }
    }

    public static final class WithPublicEqual {

        public boolean equal(Object o) {
            return false;
        }

        public boolean equal(String o) {
            return false;
        }

        public Object equal(Integer o) {
            return null;
        }

    }

}
