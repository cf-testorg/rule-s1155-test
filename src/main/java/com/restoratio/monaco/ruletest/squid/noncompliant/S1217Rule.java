package com.restoratio.monaco.ruletest.squid.noncompliant;

public class S1217Rule {

    public static class WithMethodParameter {

        public void test(Thread thread) {
            thread.run();
        }

        public void test(MyThread thread) {
            thread.run();
        }
    }

    public static class WithInMethod {

        public void testWithThread() {
            Thread thread = new Thread();
            thread.run();

            new Thread().run();
        }

        public void testWithExtending() {
            MyThread thread = new MyThread();
            thread.run();

            new MyThread().run();
        }
    }
}
