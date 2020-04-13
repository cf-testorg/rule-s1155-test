package com.restoratio.monaco.ruletest.squid.compliant;

public class S1174Rule {

	@Override
	protected void finalize() throws Throwable { //compliant. Is protected
		super.finalize();
	}
	
	public String finalize(String method) { //Should not be detected.
		return "";
	}
}
