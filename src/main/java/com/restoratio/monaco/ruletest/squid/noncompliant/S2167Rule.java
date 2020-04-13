package com.restoratio.monaco.ruletest.squid.noncompliant;

public class S2167Rule implements Comparable<S2167Rule>{

	@Override
	public int compareTo(S2167Rule o) {
		boolean condition = false;
		
		if (condition) {
		    return Integer.MIN_VALUE;  // Noncompliant
		 } else {
			 return -1;
		 }
	
	}

}
