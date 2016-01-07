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
package eu.ubitech.cyberattackanalyzer.service.blacklist.ipvoid;

import eu.ubitech.cyberattackanalyzer.service.location.freegeoip.LocationRetriever;
import eu.ubitech.cyberattackanalyzer.service.reverseip.hackertarget.VirtuahostNameRetriever;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author Panagiotis Gouvas (pgouvas@ubitech.eu)
 */
public class BlacklistRetriver implements IBlacklistStatusRetriver {

    private static final Logger logger = Logger.getLogger(BlacklistRetriver.class.getName());

    @Override
    public int getBlacklistStatus(String ipaddr) {
        int ret = 0;
        try {
            String url = "http://www.ipvoid.com/scan/"+ipaddr+"/";

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
            String responsestr = response.toString();
            //green answer is <tr><td>Blacklist Status</td><td><span class="label label-success">POSSIBLY SAFE 0/40</span></td></tr>
            //red answer is <tr><td>Blacklist Status</td><td><span class="label label-danger">BLACKLISTED 5/40</span></td></tr>
            final Pattern pattern = Pattern.compile("<tr><td>Blacklist Status</td><td>(.+?)</td></tr>");
            final Matcher matcher = pattern.matcher(responsestr);
            matcher.find();
            String result = matcher.group(1);
            if (result.indexOf("BLACKLISTED")!=-1) {
                String scorestr = result.substring(result.indexOf("BLACKLISTED")+11, result.indexOf("</span>")).trim();
                //logger.info(scorestr);
                ret=Integer.parseInt( scorestr.split("/")[0] );
            }//if
            //logger.info("logger: "+ret);
            //logger.info("response:"+ret);

        } catch (ProtocolException ex) {
            Logger.getLogger(LocationRetriever.class.getName()).log(Level.SEVERE, null, ex);
        } catch (MalformedURLException ex) {
            Logger.getLogger(VirtuahostNameRetriever.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(VirtuahostNameRetriever.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalStateException ise){
            ret = -1;
        }
        return ret;
    }//EoM

}
