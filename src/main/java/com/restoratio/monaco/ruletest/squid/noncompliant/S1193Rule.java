package com.restoratio.monaco.ruletest.squid.noncompliant;

import java.io.IOException;

public class S1193Rule {

	@Override
	protected void finalize() throws Throwable { //compliant. Is protected
		try {
  /* ... */
		} catch (Exception e) {
			if(e instanceof IOException) { /* ... */ }         // Noncompliant
			if(e instanceof NullPointerException) { /* ... */ }  // Noncompliant
		}
	}
	
	public String finalize(String method) { //Should not be detected.
		return "";
	}
}
