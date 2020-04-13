package com.restoratio.monaco.ruletest.squid.compliant;

import java.net.URL;

public class S1206Rule {

	@Override
	public boolean equals(Object obj) {
		return super.equals(obj);
		// Noncompliant - should also override "hashCode()"
	}

	@Override
	public int hashCode() {
		return 12312;
	}
}

class S1206Rule2 {

	protected boolean equals(URL u1) {
		return u1.equals(this);
	}

	protected int hashCode(URL u) {
		return System.identityHashCode(u);
	}

}
