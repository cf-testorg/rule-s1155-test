package com.restoratio.monaco.ruletest.squid.noncompliant;

public class S1174Rule {
	
	@Override
	public void finalize() throws Throwable { //non-compliant - public finalize
		super.finalize();
	}
	
}
