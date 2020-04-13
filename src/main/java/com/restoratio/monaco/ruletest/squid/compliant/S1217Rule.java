package com.restoratio.monaco.ruletest.squid.compliant;

public class S1217Rule {

    public static class PoolThread extends Thread {

    }

    public static class WithMethodParameter {

        public void test(Thread thread) {
            thread.start();
        }

        public void test(PoolThread thread) {
            thread.start();
        }
    }

    public static class WithInMethod {

        public void testWithThread() {
            Thread thread = new Thread();
            thread.start();

            new Thread().start();
        }

        public void testWithExtending() {
            PoolThread thread = new PoolThread();
            thread.start();

            new PoolThread().start();
        }
    }
}
