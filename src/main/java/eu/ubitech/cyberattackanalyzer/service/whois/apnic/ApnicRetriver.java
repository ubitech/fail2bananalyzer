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
package eu.ubitech.cyberattackanalyzer.service.whois.apnic;

import eu.ubitech.cyberattackanalyzer.service.location.freegeoip.LocationRetriever;
import eu.ubitech.cyberattackanalyzer.service.reverseip.hackertarget.VirtuahostNameRetriever;
import eu.ubitech.cyberattackanalyzer.service.whois.HostInfo;
import eu.ubitech.cyberattackanalyzer.service.whois.IWhoisInfoRetriever;
import eu.ubitech.cyberattackanalyzer.service.whois.Util;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 *
 * @author Panagiotis Gouvas (pgouvas@ubitech.eu)
 */
public class ApnicRetriver implements IWhoisInfoRetriever {

    private static final Logger logger = Logger.getLogger(ApnicRetriver.class.getName());

    /**
     *
     * view-source:http://rest.db.ripe.net/search.xml?query-string=46.4.215.41&flags=no-filtering
     *
     * @param ipaddr
     * @return
     */
    @Override
    public HostInfo getHostInfo(String ipaddr) {
        HostInfo hinfo = new HostInfo();
        try {
            String url = "https://wq.apnic.net/whois-search/query?searchtext=" + ipaddr;

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
                response.append(inputLine + "\n");
                //logger.info(":"+inputLine);
            }
            in.close();

            //print result
            String responsesrest = response.toString();
            //logger.info("response:" + responsesrest);
            
            //declare variables
            String inetnum = "";
            int range = -1;
            String netname = "";
            String provname = "";
            
            //parse output
            JSONParser parser = new JSONParser();
            Object robj = parser.parse(responsesrest);
            JSONArray array = (JSONArray) robj;
            
            for (int i=0;i<array.size();i++){
                JSONObject child = (JSONObject)array.get(i);
                String value = (String) child.get("type");
//                logger.info(value);
                //handle object
                if (value.equalsIgnoreCase("object")){
                    String objtype = (String) child.get("objectType");
                    //handle inetnum objecttype
                    if (objtype.equalsIgnoreCase("inetnum")){
                        inetnum = (String) child.get( "primaryKey" );
                        String[] ips = inetnum.split("-");
                        range = Util.calculateRange(ips[0].trim(), ips[1].trim());
                        //get attributes
                        JSONArray atarray = (JSONArray)child.get("attributes");
                        for (int j=0;j<atarray.size();j++){
                            JSONObject attrob = (JSONObject)atarray.get(j);
                            String attrname = (String) attrob.get("name"); 
                            //logger.info( "attrname: "+attrname );
                            //handle descr
                            if (attrname.trim().equalsIgnoreCase("descr")){
                                JSONArray descrarray =(JSONArray) attrob.get("values");
                                if (descrarray.size()>0) netname = (String) descrarray.get(0);
                            }//handle descr
                        }//for inetnum attribute iteration
                    }//inetnum objectype
                    
                    if (objtype.equalsIgnoreCase("route")){
                        //get attributes
                        JSONArray atarray = (JSONArray)child.get("attributes");
                        for (int j=0;j<atarray.size();j++){
                            JSONObject attrob = (JSONObject)atarray.get(j);
                            String attrname = (String) attrob.get("name"); 
                            //handle descr
                            if (attrname.trim().equalsIgnoreCase("descr")){
                                JSONArray descrarray =(JSONArray) attrob.get("values");
                                if (descrarray.size()>0) provname = (String) descrarray.get(0);
                            }//handle descr
                        }//for inetnum attribute iteration
                    }//inetnum objectype                    
                    
                }//handle objects
            }//for root elements iteration
            

            hinfo.setInetnum(inetnum);
            hinfo.setNetsize(range);
            hinfo.setNetname(netname);
            hinfo.setProvname(provname);
            logger.info("inetnum:" + inetnum);
            logger.info("range:"+range);
            logger.info("netname:" + netname);
            logger.info("provname:" + provname);

        } catch (ProtocolException ex) {
            Logger.getLogger(LocationRetriever.class.getName()).log(Level.SEVERE, null, ex);
        } catch (MalformedURLException ex) {
            Logger.getLogger(VirtuahostNameRetriever.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(VirtuahostNameRetriever.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ParseException ex) {
            Logger.getLogger(ApnicRetriver.class.getName()).log(Level.SEVERE, null, ex);
        }

        return hinfo;
    }//EoM

    public static int calculateRange(String address1, String address2) {
        int result = 0;
        result = parseIp(address2) - parseIp(address1);
        return result;
    }//EoM

    public static int parseIp(String address) {
        int result = 0;

        // iterate over each octet
        for (String part : address.split(Pattern.quote("."))) {
            // shift the previously parsed bits over by 1 byte
            result = result << 8;
            // set the low order bits to the current octet
            result |= Integer.parseInt(part);
        }
        return result;
    }//EoM    

}
