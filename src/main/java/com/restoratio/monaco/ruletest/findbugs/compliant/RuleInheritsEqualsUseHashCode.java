package com.restoratio.monaco.ruletest.findbugs.compliant;

import java.util.Objects;

public class RuleInheritsEqualsUseHashCode {

    public static class WithHashCodeAndEquals {

        public static abstract class AbstractHashCodeAndEquals {

            @Override
            public int hashCode() {
                return 0;
            }

            @Override
            public boolean equals(Object o) {
                return o instanceof AbstractHashCodeAndEquals;
            }
        }

        public static class OverwriteNothing extends AbstractHashCodeAndEquals {

        }

        public static class OverwriteEquals extends AbstractHashCodeAndEquals {

            @Override
            public boolean equals(Object o) {
                return o instanceof AbstractHashCodeAndEquals;
            }
        }

        public static class OverwriteHashCode extends AbstractHashCodeAndEquals {

            @Override
            public int hashCode() {
                return 1;
            }
        }
    }

    public static class WithEmptyAbstract {

        public static abstract class AbstractEmpty {

        }

        public static class EmptyOverwriteHashCode extends AbstractEmpty {

            @Override
            public int hashCode() {
                return 0;
            }
        }

        public static class EmptyOverwriteEquals extends AbstractEmpty {

            @Override
            public boolean equals(Object o) {
                return o instanceof EmptyOverwriteEquals;
            }
        }
    }

    public static class WithNonAbstractBase {

        public static class BaseEquals {

            @Override
            public boolean equals(Object o) {
                return o instanceof BaseEquals;
            }
        }

        public static class InheritBaseEquals extends BaseEquals {

        }
    }

    public static class WithAbstractEquals {

        public static abstract class AbstractEquals {

            @Override
            public boolean equals(Object o) {
                return o instanceof AbstractEquals;
            }
        }

        public static class OverwriteEqualsInNonAbstract extends AbstractEquals {

            @Override
            public boolean equals(Object o) {
                return o instanceof OverwriteEqualsInNonAbstract;
            }
        }

        public static class OverwriteHashCodeInNonAbstract extends AbstractEquals {

            @Override
            public int hashCode() {
                return super.hashCode();
            }
        }

        public static class InheritFromNonAbstract extends OverwriteEqualsInNonAbstract {

        }

        public static class InheritFromNonAbstractHashCode extends OverwriteHashCodeInNonAbstract {

        }
    }

    public static class WithNonAbstractHashCode {

        public static abstract class AbstractHashCode {

            @Override
            public int hashCode() {
                return super.hashCode();
            }
        }

        public static class OverwriteEquals extends AbstractHashCode {

            @Override
            public boolean equals(Object o) {
                return o instanceof AbstractHashCode;
            }
        }
    }

    public static class WithNonObjectEquals {

        public static abstract class AbstractNonObjectEquals {

            public boolean equals(String o) {
                return Objects.nonNull(o);
            }
        }

        public static class InheritFromNonObject extends AbstractNonObjectEquals {

        }

    }
}
