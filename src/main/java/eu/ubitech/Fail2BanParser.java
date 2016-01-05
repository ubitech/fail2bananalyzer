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
package eu.ubitech;

import eu.ubitech.cyberattackanalyzer.parser.AttackLogParser;
import eu.ubitech.cyberattackanalyzer.service.location.freegeoip.LocationRetriever;


/**
 *
 * @author Panagiotis Gouvas (pgouvas@ubitech.eu)
 */
public class Fail2BanParser {

    public static void main(String[] args) {
        AttackLogParser.parseFile("inputdata/attacks.log");
        LocationRetriever locretr = new LocationRetriever();
        locretr.inferLocation("43.229.53.56");
    }//EoMain
    
    //whois
    
    //Geolocation
    //http://freegeoip.net/xml/www.in.gr
    
    //reverse IP 
    //http://www.yougetsignal.com/tools/web-sites-on-web-server/
    
    //blacklist info
    //https://www.projecthoneypot.org/httpbl_api.php 
    //http://mxtoolbox.com/blacklists.aspx 
    
}//EoC
