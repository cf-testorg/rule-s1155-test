package com.restoratio.monaco.ruletest.squid.compliant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class S1166Rule {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public void testException() {
        try {
  /* ... */
        } catch (Exception e) {
            logger.error("Error",e);  // exception is logged
        }

        try {
  /* ... */
        } catch (Exception e) {
            throw new RuntimeException(e);   // exception stack trace is propagated
        }

        try {
  /* ... */
        } catch (RuntimeException e) {
            doSomething();
            throw e;  // original exception passed forward
        } catch (Exception e) {
            throw new RuntimeException(e);  // Conversion into unchecked exception is also allowed
        }

    }


    public void doSomething() {

    }

}
