package com.restoratio.monaco.ruletest.squid.noncompliant;

import java.text.MessageFormat;

public class S2275Rule {
	private void aNonComplaintMethod() {

		int c=2011;
		int value = 99;
		Object unUsedObject = null;

		String format="";
		format += String.format("The value of my integer is %d", "Hello World");
		format += String.format("The value of PI is %f", "PI");
		format += String.format("Duke's Birthday year is %tX", c);
		format += String.format("Display %0$d and then %d", 1);
		format += String.format("Not enough arguments %d and %d", 1);
		format += String.format("%< is equals to %d", 2);

		MessageFormat.format("Result {1}.", value);
		MessageFormat.format("Result {{0}.", value);

		MessageFormat.format("Result ' {0}", value);
		
		format +="x";
	}

	private void aComplaintOne() {
		int c=2011;
		int value = 99;
		Object myObject = null;
		
		String format="";
		format += String.format("The value of my integer is %d", 3);
		format += String.format("The value of PI is %f", Math.PI);
		format += String.format("Duke's Birthday year is %tY", c);
		format += String.format("Display %1$d and then %d", 1);
		format += String.format("Not enough arguments %d and %d", 1, 2);
		format += String.format("%d is equals to %<", 2);
		

		MessageFormat.format("Result {0}.", value);
		MessageFormat.format("Result {0} & {1}.", value, value);
		MessageFormat.format("Result {0}.", myObject);
		
		format +="x";
	}

	public void duh() {
		int i = -99;
		this.aNonComplaintMethod();  //Some Comment
		this.aComplaintOne();
		
		String.format("%d",  i);
	}
}
