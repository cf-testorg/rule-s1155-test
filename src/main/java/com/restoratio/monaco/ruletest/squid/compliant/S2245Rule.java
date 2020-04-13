package com.restoratio.monaco.ruletest.squid.compliant;

import java.security.SecureRandom;
import com.restoratio.monaco.ruletest.helpers.squid.MySecureRandom;
import com.restoratio.monaco.ruletest.helpers.squid.Random;

public class S2245Rule {

    private final Random r = new Random(12);

    private final java.util.Random mySecureRandom = new MySecureRandom();

    public void doSomething() {
        java.util.Random random = new SecureRandom();
        byte bytes[] = new byte[20];
        random.nextBytes(bytes);
    }

}
