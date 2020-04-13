package com.restoratio.monaco.ruletest.squid.compliant;

public class S2445Rule {

	private String color = "red";
	private final Object lockObj = new Object();

	private void doSomething() {
		synchronized (lockObj) { // compliant; 
	    color = "green";
	  }
	}

}
