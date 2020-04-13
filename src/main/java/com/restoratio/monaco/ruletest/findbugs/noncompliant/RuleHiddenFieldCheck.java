package com.restoratio.monaco.ruletest.findbugs.noncompliant;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class RuleHiddenFieldCheck {

    private String privateOne;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    private static String privateTwo;
    ;;;
    private static final String privateThree = "EMPTY";

    public String publicOne;
    public static String publicTwo;
    public static final String publicThree = "EMPTY";

    private ByteArrayInputStream stream = new ByteArrayInputStream(new byte[]{1, 2, 3});

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

    public class FirstLevelInner {

        public class SecondLevelInner {

            public void methodOne() {
                Double privateOne = 15.3;
                Short privateTwo = 3;
                Integer privateThree = 12;

                Integer publicOne = 15;
                Double publicTwo = 3.4d;
                Short publicThree = 12;

                String otherValue = "TEST";
            }
        }
    }

    public void methodOne() {
        Integer privateOne = 15;
        Double privateTwo = 3.4d;
        Short privateThree = 12;

        Integer publicOne = 15;
        Double publicTwo = 3.4d;
        Short publicThree = 12;

        String otherValue = "TEST";
    }

    public void methodTwo() throws IOException {
        for (int privateOne = 0; privateOne < 10; privateOne++) {
            System.out.println(privateOne);
        }
        for (int i = 0; i < 5; i++) {
            System.out.println(privateOne);
        }
        try (FileInputStream stream = new FileInputStream(new File("test"))) {

        }
    }


}
