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
import eu.ubitech.cyberattackanalyzer.service.portscanning.Port;
import eu.ubitech.cyberattackanalyzer.service.portscanning.ScanResult;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.xml.sax.InputSource;

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
            //String[] command = {"echo '!vmadmin!' | sudo -S  nmap  -O -oX nmap95.163.107.202.xml   95.163.107.202"};
            String[] command = {"/bin/bash", "-c", "echo '!vmadmin!' | sudo -S  nmap  -O -oX output/nmap" + ipaddr + ".xml " + ipaddr};
            ProcessBuilder probuilder = new ProcessBuilder(command);
            //You can set up your work directory
            //probuilder.directory(new File("c:\\xyzwsdemo"));
            Process process = probuilder.start();
            //Read out dir output
            InputStream is = process.getInputStream();
            InputStreamReader isr = new InputStreamReader(is);
            BufferedReader br = new BufferedReader(isr);
            String line;
            String responsestrnonxml = "";
            //logger.info("Output of running %s is:\n"+Arrays.toString(command));
            while ((line = br.readLine()) != null) {
                responsestrnonxml += line + "\r";
                //logger.info(line);
            }
            int exitValue = process.waitFor();
            //logger.info("Nmap finished:\n" + responsestrnonxml);
            String responsestrxml = "";
            //load xml from file
            responsestrxml = readFile("output/nmap" + ipaddr + ".xml", Charset.defaultCharset());
            //xpath handling
            InputSource xmlsource = new InputSource(new StringReader(responsestrxml));
            XPath xpath = XPathFactory.newInstance().newXPath();
            Object responseobject = xpath.evaluate("/nmaprun", xmlsource, XPathConstants.NODE);
            String numofports = "0";
            numofports = xpath.evaluate("count(//host/ports/port)", responseobject);
            //logger.info("numofports: " + numofports);

            int count = Integer.parseInt(numofports);
            scanresult.setAmount(count);
            if (count>0) {
                ArrayList list = new ArrayList();
                //initialize 
                scanresult.setPorts(list);
                
                for (int i = 0; i < count; i++) {
                    String portid = xpath.evaluate("//host/ports/port[" + (i + 1) + "]/@portid", responseobject);
                    String portname = xpath.evaluate("//host/ports/port[" + (i + 1) + "]/service/@name", responseobject);
//                    logger.info("portid:" + portid);
//                    logger.info("name:" + portname);
                    Port port = new Port(portid, portname);
                    scanresult.getPorts().add(port);
                }//for
                String os = "";
                os = xpath.evaluate("//os/osmatch/@name", responseobject);
                scanresult.setOs(os);
//              logger.info("os:" + os);                
            }
        } //EoM
        catch (IOException ex) {
            Logger.getLogger(NMapScannerExecutor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InterruptedException ex) {
            Logger.getLogger(NMapScannerExecutor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (XPathExpressionException ex) {
            Logger.getLogger(NMapScannerExecutor.class.getName()).log(Level.SEVERE, null, ex);
        }

        return scanresult;
    }//EoM

    static String readFile(String path, Charset encoding) throws IOException {
        byte[] encoded = Files.readAllBytes(Paths.get(path));
        return new String(encoded, encoding);
    }

}//EoM
