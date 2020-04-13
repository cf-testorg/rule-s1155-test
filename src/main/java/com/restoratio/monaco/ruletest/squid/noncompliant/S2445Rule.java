package com.restoratio.monaco.ruletest.squid.noncompliant;

public class S2445Rule {

	private String color = "red";

	private void doSomething() {
		synchronized (color) { // Noncompliant; lock is actually on object
								// instance "red" referred to by the color
								// variable
			color = "green"; // other threads now allowed into this block
		}
	}

	private void doOtherThing(String colorParam) {
		synchronized (colorParam) { // Noncompliant; lock is actually on a
									// parameter instance "red" referred to by
									// the color variable
			color = "green"; // other threads now allowed into this block
		}
	}
}
