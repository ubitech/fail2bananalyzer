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
package eu.ubitech.cyberattackanalyzer.service.whois.ripe;

import eu.ubitech.cyberattackanalyzer.service.location.freegeoip.LocationRetriever;
import eu.ubitech.cyberattackanalyzer.service.reverseip.hackertarget.VirtuahostNameRetriever;
import eu.ubitech.cyberattackanalyzer.service.whois.HostInfo;
import eu.ubitech.cyberattackanalyzer.service.whois.IWhoisInfoRetriever;
import eu.ubitech.cyberattackanalyzer.service.whois.Util;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.xml.sax.InputSource;

/**
 *
 * @author Panagiotis Gouvas (pgouvas@ubitech.eu)
 */
public class RipeRetriver implements IWhoisInfoRetriever {

    private static final Logger logger = Logger.getLogger(RipeRetriver.class.getName());        
    
    /**
     *
     *  view-source:http://rest.db.ripe.net/search.xml?query-string=46.4.215.41&flags=no-filtering
     * @param ipaddr
     * @return
     */
    @Override
    public HostInfo getHostInfo(String ipaddr) {
       HostInfo hinfo = new HostInfo();        
       try {
            String url = "http://rest.db.ripe.net/search.xml?query-string="+ipaddr+"&flags=no-filtering";

            URL obj = new URL(url);
            HttpURLConnection con = (HttpURLConnection) obj.openConnection();
            // optional default is GET
            con.setRequestMethod("GET");

            int responseCode = con.getResponseCode();
//            logger.info("\nSending 'GET' request to URL : " + url);
//            logger.info("Response Code : " + responseCode);

            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuffer response = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine+"\n");
                //logger.info(":"+inputLine);
            }
            in.close();

            //print result
            String responsestrxml = response.toString();
            //logger.info("response:"+responsestrxml);

            InputSource xmlsource = new InputSource(new StringReader(responsestrxml));
            XPath xpath = XPathFactory.newInstance().newXPath();
            Object responseobject = xpath.evaluate("/whois-resources", xmlsource, XPathConstants.NODE);
            //inetnum
            String inetnum = xpath.evaluate("//objects/object[@type='inetnum']/primary-key/attribute[@name='inetnum']/@value", responseobject);                
            //String netname = xpath.evaluate("//objects/object[@type='inetnum']/attributes/attribute[@name='netname']/@value", responseobject);    
            String descr = xpath.evaluate("//objects/object[@type='inetnum']/attributes/attribute[@name='descr']/@value", responseobject);  
            //String orgname = xpath.evaluate("//objects/object[@type='organisation']/attributes/attribute[@name='org-name']/@value", responseobject);  
            hinfo.setInetnum(inetnum);
            hinfo.setNetname(descr);
            //TODO fetch provname through route
            String[] ips = inetnum.split("-");
            int range = Util.calculateRange(ips[0].trim(), ips[1].trim());
            hinfo.setNetsize(range);
//            logger.info("inetnum:"+inetnum);
//            logger.info("range:"+range);
//            logger.info("netname:"+netname);
//            logger.info("descr:"+descr);
//            logger.info("orgname:"+orgname);
            
        } catch (ProtocolException ex) {
            Logger.getLogger(LocationRetriever.class.getName()).log(Level.SEVERE, null, ex);
        } catch (MalformedURLException ex) {
            Logger.getLogger(VirtuahostNameRetriever.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(VirtuahostNameRetriever.class.getName()).log(Level.SEVERE, null, ex);
        } catch (XPathExpressionException ex) {
            Logger.getLogger(RipeRetriver.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return hinfo;
    }//EoM

}