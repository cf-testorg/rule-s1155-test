package com.restoratio.monaco.ruletest.squid.noncompliant;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class S1166Rule {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public void testException() {

        try {
  /* ... */
        } catch (Exception e) {   // Noncompliant - exception is lost
            logger.info("context");
        }

        try {
  /* ... */
        } catch (Exception e) {  // Noncompliant - exception is lost (only message is preserved)
            logger.info(e.getMessage());
        }

        try {
  /* ... */
        } catch (Exception e) {  // Noncompliant - original exception is lost
            throw new RuntimeException("context");
        }
    }


    public void doSomething() {

    }

}
