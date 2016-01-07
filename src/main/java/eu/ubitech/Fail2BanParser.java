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
import eu.ubitech.cyberattackanalyzer.service.blacklist.ipvoid.BlacklistRetriver;
import eu.ubitech.cyberattackanalyzer.service.location.Location;
import eu.ubitech.cyberattackanalyzer.service.location.freegeoip.LocationRetriever;
import eu.ubitech.cyberattackanalyzer.service.portscanning.custom.CustomPortScanExecutor;
import eu.ubitech.cyberattackanalyzer.service.portscanning.nmap.NMapScannerExecutor;
import eu.ubitech.cyberattackanalyzer.service.reverseip.VirtualHostname;
import eu.ubitech.cyberattackanalyzer.service.reverseip.hackertarget.VirtuahostNameRetriever;
import eu.ubitech.cyberattackanalyzer.service.whois.ripe.WhoisInfoRetriver;
import java.util.ArrayList;
import java.util.logging.Logger;
import javax.xml.xpath.XPathExpressionException;


/**
 * while inside the input folder
 * scp ubuntu@192.168.3.200:/var/log/fail2ban.log .
 * cat fail2ban.log | grep Ban | cut -d" " -f1,2,7 > attacks.log
 * 
 * @author Panagiotis Gouvas (pgouvas@ubitech.eu)
 */
public class Fail2BanParser {

    private static final Logger logger = Logger.getLogger(Fail2BanParser.class.getName());    
    
    public static void main(String[] args) throws XPathExpressionException {
        //main
//        AttackLogParser.parseFile("inputdata/attacks.log");
        //service1 - location
//        LocationRetriever locretriever = new LocationRetriever();
//        Location location = locretriever.inferLocation("43.229.53.56");        
        //service2 - reverse ip
//        VirtuahostNameRetriever vhostretriver = new VirtuahostNameRetriever();
//        ArrayList<VirtualHostname> vhosts = vhostretriver.retriverVirtualHosts("46.4.215.41");
//        logger.info("size:"+vhosts.size());
        //service3 - whois
//        WhoisInfoRetriver whoisretriver = new WhoisInfoRetriver();
//        whoisretriver.getHostInfo("46.4.215.41");
        //service4 - scan result
//        CustomPortScanExecutor portscanner = new CustomPortScanExecutor();
//        portscanner.scanTarget("43.229.53.56");
//          BlacklistRetriver blr = new BlacklistRetriver();         
//          blr.getBlacklistStatus("213.249.38.66");
//          blr.getBlacklistStatus("43.229.53.56");
        NMapScannerExecutor nMapScannerExecutor = new NMapScannerExecutor();
        nMapScannerExecutor.scanTarget("95.163.107.202");
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
