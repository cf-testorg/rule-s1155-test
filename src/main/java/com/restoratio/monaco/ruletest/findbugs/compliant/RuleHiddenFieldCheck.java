package com.restoratio.monaco.ruletest.findbugs.compliant;

public class RuleHiddenFieldCheck {

    private String privateOne;
    private static String privateTwo;
    private static final String privateThree = "EMPTY";

    public String publicOne;
    public static String publicTwo;
    public static final String publicThree = "EMPTY";

    static {
        Integer privateTwo = 5;
    }


    public static class InnerStaticClass {
        public class SimpleInnerClass {
            public void methodOne() {
                Short privateOne = 15;
                Integer privateTwo = 3;
                Double privateThree = 12.4d;

                Integer publicOne = 15;
                Double publicTwo = 3.4d;
                Short publicThree = 12;

                String otherValue = "TEST";
            }
        }
    }

}
