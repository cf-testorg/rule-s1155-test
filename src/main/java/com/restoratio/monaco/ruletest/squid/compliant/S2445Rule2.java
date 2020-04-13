package com.restoratio.monaco.ruletest.squid.compliant;

public class S2445Rule2 {

	private String color = "red";

	private void doSomething() {
		synchronized (color) { 
			System.out.println(color); 	// compliant for sonar, not assignment on variable
	  }
	}

}
