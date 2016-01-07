/*
 *  Copyright 2015-2016 Fail2BanAnalyzer
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package eu.ubitech.cyberattackanalyzer.service.portscanning.nmap;

import eu.ubitech.cyberattackanalyzer.service.portscanning.IPortScanExecutor;
import eu.ubitech.cyberattackanalyzer.service.portscanning.ScanResult;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Panagiotis Gouvas (pgouvas@ubitech.eu)
 */
public class NMapScannerExecutor implements IPortScanExecutor {

    private static final Logger logger = Logger.getLogger(NMapScannerExecutor.class.getName());

    @Override
    public ScanResult scanTarget(String ipaddr) {
        ScanResult scanresult = new ScanResult();
        try {
            //String[] command = {"echo' !vmadmin!' | sudo -S  nmap  -O -oX nmap95.163.107.202.xml   95.163.107.202"};
            String[] command = {"/bin/bash","echo","a"};
            ProcessBuilder probuilder = new ProcessBuilder(command);
            //You can set up your work directory
            //probuilder.directory(new File("c:\\xyzwsdemo"));
            Process process = probuilder.start();
            //Read out dir output
            InputStream is = process.getInputStream();
            InputStreamReader isr = new InputStreamReader(is);
            BufferedReader br = new BufferedReader(isr);
            String line;
            System.out.printf("Output of running %s is:\n",
                    Arrays.toString(command));
            while ((line = br.readLine()) != null) {
                System.out.println(line);
            }
            int exitValue = process.waitFor();
            logger.info("finished");

        } //EoM
        catch (IOException ex) {
            Logger.getLogger(NMapScannerExecutor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InterruptedException ex) {
            Logger.getLogger(NMapScannerExecutor.class.getName()).log(Level.SEVERE, null, ex);
        }
        return scanresult;
    }//EoM

}//EoM
