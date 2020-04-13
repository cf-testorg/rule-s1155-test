package com.restoratio.monaco.ruletest.squid.noncompliant;

public class S1871Rule {

	public void anIfMethod(int a) {

		if (a >= 0 && a < 10) {
			doFirstThing();
			doTheThing();
		} else if (a >= 10 && a < 20) {
			doTheOtherThing();
		} else if (a >= 20 && a < 50) {
			doFirstThing();
			doTheThing(); // Noncompliant; duplicates first condition
		} else {
			doTheRest();
		}
	}

	private void doTheOtherThing() {
		// TODO Auto-generated method stub

	}

	private void doTheThing() {
		// TODO Auto-generated method stub

	}

	public void aSwitchMethod(int i) {

		switch (i) {
		case 1:
			doFirstThing();
			doSomething();
			break;
		case 2:
			doSomethingDifferent();
			break;
		case 3: // Noncompliant; duplicates case 1's implementation
			doFirstThing();
			doSomething();
			break;
		case 4:
			doSomethingDifferent();  // compliant; Only 1 implementation line (case 2)
			break;
		default:
			doTheRest();
		}

	}

	private void doTheRest() {
		// TODO Auto-generated method stub

	}

	private void doSomethingDifferent() {
		// TODO Auto-generated method stub

	}

	private void doSomething() {
		// TODO Auto-generated method stub

	}

	private void doFirstThing() {
		// TODO Auto-generated method stub

	}

}
