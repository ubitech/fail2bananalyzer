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
package eu.ubitech.cyberattackanalyzer.service.reverseip.hackertarget;

import eu.ubitech.cyberattackanalyzer.service.location.freegeoip.LocationRetriever;
import eu.ubitech.cyberattackanalyzer.service.reverseip.IVirtuahostNameRetriever;
import eu.ubitech.cyberattackanalyzer.service.reverseip.VirtualHostname;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Panagiotis Gouvas (pgouvas@ubitech.eu)
 */
public class VirtuahostNameRetriever implements IVirtuahostNameRetriever{

    private static final Logger logger = Logger.getLogger(VirtuahostNameRetriever.class.getName());    
    
    /**
     * Uses the api of http://api.hackertarget.com/reverseiplookup/?q=46.4.215.41 in order to resolve the target
     * @param ipaddr
     * @return
     */
    @Override
    public ArrayList<VirtualHostname> retriverVirtualHosts(String ipaddr) {
        ArrayList<VirtualHostname> vhosts = new ArrayList();
        
        try {
            String url = "http://api.hackertarget.com/reverseiplookup/?q=" + ipaddr;

            URL obj = new URL(url);
            Proxy proxy = new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", 9050));            
            HttpURLConnection con = (HttpURLConnection) obj.openConnection(proxy);
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
            String responsestr = response.toString();
            //logger.info("response:"+responsestr);
            String[] uris = responsestr.split("\n");
            for (String uri : uris) {
                //add only if exists
                if (uri.indexOf("No records found")==-1)
                  vhosts.add(new VirtualHostname(uri));
            }//for
                                
        } catch (ProtocolException ex) {
            Logger.getLogger(LocationRetriever.class.getName()).log(Level.SEVERE, null, ex);
        } catch (MalformedURLException ex) {
            Logger.getLogger(VirtuahostNameRetriever.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(VirtuahostNameRetriever.class.getName()).log(Level.SEVERE, null, ex);
        }
        return vhosts;
    }//EoM
    
}