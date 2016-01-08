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
package eu.ubitech.cyberattackanalyzer.service.whois;

import java.util.regex.Pattern;

/**
 *
 * @author Panagiotis Gouvas (pgouvas@ubitech.eu)
 */
public class Util {
    
    public static int calculateRange(String address1,String address2){
        int result=0;
        result = parseIp(address2)-parseIp(address1);
        return result;
    }//EoM
    
    public static int parseIp(String address) {
        int result = 0;

        // iterate over each octet
        for(String part : address.split(Pattern.quote("."))) {
            // shift the previously parsed bits over by 1 byte
            result = result << 8;
            // set the low order bits to the current octet
            result |= Integer.parseInt(part);
        }
        return result;
    }//EoM        
    
}
