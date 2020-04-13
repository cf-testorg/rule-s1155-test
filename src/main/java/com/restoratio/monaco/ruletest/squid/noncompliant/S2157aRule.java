package com.restoratio.monaco.ruletest.squid.noncompliant;

import com.restoratio.monaco.ruletest.squid.compliant.Person;
import java.util.List;

public class S2157aRule implements Cloneable {

    private Person coach;
    private List<Person> players;

    public void addPlayer(Person p) {
        Person p1 = p;
        System.out.println(p1);
    }

    public Person getCoach() {
        return new Person();
    }

}
