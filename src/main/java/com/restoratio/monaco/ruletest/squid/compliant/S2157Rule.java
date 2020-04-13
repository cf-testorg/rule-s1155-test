package com.restoratio.monaco.ruletest.squid.compliant;

import java.util.List;

public class S2157Rule implements CloneableTest {

    private Person coach;
    private List<Person> players;

    public void addPlayer(Person p) {
        Person p1 = p;
        System.out.println(p1);
    }

    public Person getCoach() {
        return new Person();
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        S2157Rule clone = (S2157Rule) super.clone();
        System.out.println(clone);
        return clone;
    }

}
