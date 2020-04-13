package com.restoratio.monaco.ruletest.squid.compliant;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class S2737Rule {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public String readFile(File f) throws IOException {
        StringBuilder sb = new StringBuilder();
        FileReader fileReader = null;
        try {
            String fileName = "filename";
            fileReader = new FileReader(fileName);
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            fileReader.close();
        } catch (IOException e) {
            logger.error("Error log",e);
            throw e;
        } finally {
            if (fileReader != null) {
                fileReader.close();
            }
        }
        return sb.toString();
    }

    public String readFileCase2(File f) throws IOException {
        StringBuilder sb = new StringBuilder();
        FileReader fileReader = null;
        try {
            String fileName = "filename";
            fileReader = new FileReader(fileName);
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            fileReader.close();
        } catch (IOException e) {
            throw e;
        } catch (RuntimeException e) {
            logger.error("Error log", e);
        } finally {
            if (fileReader != null) {
                fileReader.close();
            }
        }
        return sb.toString();
    }
}
