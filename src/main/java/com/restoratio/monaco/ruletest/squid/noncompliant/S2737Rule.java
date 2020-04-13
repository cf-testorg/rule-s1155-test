package com.restoratio.monaco.ruletest.squid.noncompliant;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

public class S2737Rule {

    public String readFile(File f) throws IOException {
        StringBuilder sb = new StringBuilder();
        FileReader fileReader = null;
        try {
            String fileName = "filename";
            fileReader = new FileReader(fileName);
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            fileReader.close();
        } catch (IOException e) {  // Noncompliant
            throw e;
        } finally {
            if (fileReader != null) {
                fileReader.close();
            }
        }
        return sb.toString();
    }
}
