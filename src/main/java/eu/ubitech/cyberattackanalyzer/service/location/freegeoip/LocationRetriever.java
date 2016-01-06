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
package eu.ubitech.cyberattackanalyzer.service.location.freegeoip;

import eu.ubitech.cyberattackanalyzer.parser.AttackLogParser;
import eu.ubitech.cyberattackanalyzer.service.location.ILocationRetriever;
import eu.ubitech.cyberattackanalyzer.service.location.Location;
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
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.xml.sax.InputSource;

/**
 *
 * @author Panagiotis Gouvas (pgouvas@ubitech.eu)
 */
public class LocationRetriever implements ILocationRetriever {

    private static final Logger logger = Logger.getLogger(LocationRetriever.class.getName());

    /**
     *
     * @param ipaddress
     * @return a String with the following format
     * <?xml version="1.0" encoding="UTF-8"?><Response>	<IP>43.229.53.56</IP>
     * <CountryCode>HK</CountryCode>	<CountryName>Hong Kong</CountryName>
     * <RegionCode></RegionCode>	<RegionName></RegionName>	<City></City>
     * <ZipCode></ZipCode>	<TimeZone>Asia/Hong_Kong</TimeZone>
     * <Latitude>22.25</Latitude>	<Longitude>114.1667</Longitude>
     * <MetroCode>0</MetroCode></Response>
     */
    @Override
    public Location inferLocation(String ipaddress) {

        Location location = new Location();
        try {
            String url = "http://freegeoip.net/xml/" + ipaddress;

            URL obj = new URL(url);
            HttpURLConnection con = (HttpURLConnection) obj.openConnection();
            // optional default is GET
            con.setRequestMethod("GET");

            int responseCode = con.getResponseCode();
            logger.info("\nSending 'GET' request to URL : " + url);
            logger.info("Response Code : " + responseCode);

            BufferedReader in = new BufferedReader(
                    new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuffer response = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();

            //print result
            String responsexmlstr = response.toString();

            //logger.info("Location element:" + responsexmlstr);

            InputSource xmlsource = new InputSource(new StringReader(responsexmlstr));
            XPath xpath = XPathFactory.newInstance().newXPath();
            //<?xml version="1.0" encoding="UTF-8"?><Response>	<IP>43.229.53.56</IP>	<CountryCode>HK</CountryCode>	<CountryName>Hong Kong</CountryName>	<RegionCode></RegionCode>	<RegionName></RegionName>	<City></City>	<ZipCode></ZipCode>	<TimeZone>Asia/Hong_Kong</TimeZone>	<Latitude>22.25</Latitude>	<Longitude>114.1667</Longitude>	<MetroCode>0</MetroCode></Response>
            Object responsexml = xpath.evaluate("/Response", xmlsource, XPathConstants.NODE);
            //IP
            String IP = xpath.evaluate("IP", responsexml);
            location.setIP(IP);
            //CountryCode
            String CountryCode = xpath.evaluate("CountryCode", responsexml);
            location.setCountryCode(CountryCode);
            //CountryName
            String CountryName = xpath.evaluate("CountryName", responsexml);
            location.setCountryName(CountryName);
            //RegionCode
            String RegionCode = xpath.evaluate("RegionCode", responsexml);
            location.setRegionCode(RegionCode);
            //RegionName
            String RegionName = xpath.evaluate("RegionName", responsexml);
            location.setRegionName(RegionName);
            //City
            String City = xpath.evaluate("City", responsexml);
            location.setCity(City);
            //ZipCode
            String ZipCode = xpath.evaluate("ZipCode", responsexml);
            location.setZipCode(ZipCode);
            //TimeZone
            String TimeZone = xpath.evaluate("TimeZone", responsexml);
            location.setTimeZone(TimeZone);
            //Latitude
            String Latitude = xpath.evaluate("Latitude", responsexml);
            location.setLatitude(Latitude);
            //Longitude
            String Longitude = xpath.evaluate("Longitude", responsexml);
            location.setLongitude(Longitude);
            //MetroCode
            String MetroCode = xpath.evaluate("MetroCode", responsexml);
            location.setMetroCode(MetroCode);

//            logger.log(Level.INFO, "Location for: {0}", IP);
//            logger.info(CountryCode);
//            logger.info(CountryName);
//            logger.info(RegionCode);
//            logger.info(RegionName);
//            logger.info(City);
//            logger.info(ZipCode);
//            logger.info(TimeZone);
//            logger.info(Latitude);
//            logger.info(Longitude);
//            logger.info(MetroCode);

        } catch (ProtocolException ex) {
            Logger.getLogger(LocationRetriever.class.getName()).log(Level.SEVERE, null, ex);
        } catch (MalformedURLException ex) {
            Logger.getLogger(LocationRetriever.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(LocationRetriever.class.getName()).log(Level.SEVERE, null, ex);
        } catch (XPathExpressionException ex) {
            Logger.getLogger(LocationRetriever.class.getName()).log(Level.SEVERE, null, ex);
        }
        return location;
    }//EoM

}//EoC
