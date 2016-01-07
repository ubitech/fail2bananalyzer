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
package eu.ubitech.cyberattackanalyzer.service.whois.raw;

import eu.ubitech.cyberattackanalyzer.parser.AttackLogParser;
import eu.ubitech.cyberattackanalyzer.service.whois.HostInfo;
import eu.ubitech.cyberattackanalyzer.service.whois.IWhoisInfoRetriever;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.net.whois.WhoisClient;

/**
 *
 * @author Panagiotis Gouvas (pgouvas@ubitech.eu)
 */
public class RawWhoisRetriever implements IWhoisInfoRetriever {

    private static final Logger logger = Logger.getLogger(RawWhoisRetriever.class.getName());
    public static final String WHOIS_SERVER = "whois.apnic.net";
    public static final int WHOIS_PORT = 43;

    @Override
    public HostInfo getHostInfo(String ipaddr) {
        HostInfo hinfo = new HostInfo();
        try {
            WhoisClient whoisClient = new WhoisClient();
            whoisClient.connect(WHOIS_SERVER, WHOIS_PORT);
            String results = whoisClient.query(ipaddr);
            logger.info(results);
        } //EoM
        catch (IOException ex) {
            Logger.getLogger(RawWhoisRetriever.class.getName()).log(Level.SEVERE, null, ex);
        }
        return hinfo;
    }//EoM

}//EoC
