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
package eu.ubitech.cyberattackanalyzer.parser;

import eu.ubitech.cyberattackanalyzer.model.Attack;
import eu.ubitech.cyberattackanalyzer.model.Attack.DateDescriptor;
import eu.ubitech.cyberattackanalyzer.model.Attack.IPDescriptor;
import eu.ubitech.cyberattackanalyzer.model.ObjectFactory;
import eu.ubitech.cyberattackanalyzer.service.location.Location;
import eu.ubitech.cyberattackanalyzer.service.location.freegeoip.LocationRetriever;
import eu.ubitech.cyberattackanalyzer.service.reverseip.VirtualHostname;
import eu.ubitech.cyberattackanalyzer.service.reverseip.hackertarget.VirtuahostNameRetriever;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.PropertyException;

/**
 *
 * @author vmadmin
 */
public class AttackLogParser {

    private static final Logger logger = Logger.getLogger(AttackLogParser.class.getName());

    public static void parseFile(String filename) {
        //read file into stream, try-with-resources
        try (Stream<String> stream = Files.lines(Paths.get(filename))) {
            stream.forEach(AttackLogParser::handleAttack);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }//EoM parseFile

    /**
     *
     * @param attackdescr is a string that is formatted using the following
     * notation 2015-03-16 07:02:01,684 77.236.97.26
     */
    public static void handleAttack(String attackdescr) {
        

        //parse attack descriptor
        String[] parts = attackdescr.split(" ");        
        String datestr = parts[0].trim();
        String timestr = parts[1].trim();
        String ipstr = parts[2].trim();
        
        logger.info(ipstr);
                
        //STEP-1 create the attack object and its root elements
        ObjectFactory factory = new ObjectFactory();
        Attack attack = factory.createAttack();
        IPDescriptor ipdescr = factory.createAttackIPDescriptor();
        DateDescriptor datedescriptor = factory.createAttackDateDescriptor();
        Attack.MaliciousActionDescriptor maliciousActionDescriptor = factory.createAttackMaliciousActionDescriptor();
        
        //STEP-2 create IP descriptor
        ipdescr.setIPAddress(ipstr);
        //---location
        //define retriever
        LocationRetriever locretriever = new LocationRetriever();
        Location location = locretriever.inferLocation(ipstr); 
        //define xml element
        IPDescriptor.LocationDescriptor locationDescriptor = factory.createAttackIPDescriptorLocationDescriptor();
        //fill xml element
        locationDescriptor.setCountryName(location.getCountryName());
        locationDescriptor.setCountryCode(location.getCountryCode());
        locationDescriptor.setRegionName(location.getRegionName());
        locationDescriptor.setRegionCode(location.getRegionCode());
        locationDescriptor.setCity(location.getCity());
        locationDescriptor.setZipCode(location.getZipCode());
        locationDescriptor.setTimeZone(location.getTimeZone());
        locationDescriptor.setLatitude(location.getLatitude());
        locationDescriptor.setLongitude(location.getLongitude());
        locationDescriptor.setMetroCode(location.getMetroCode());
        //add it to ipdescr
        ipdescr.setLocationDescriptor(locationDescriptor);
        
        //--reverse ip
        //define retriver
        VirtuahostNameRetriever vhostretriver = new VirtuahostNameRetriever();
        ArrayList<VirtualHostname> vhosts = vhostretriver.retriverVirtualHosts(ipstr);
        //define xml element
        IPDescriptor.ReverseIPDescriptor reverseIPDescriptor = factory.createAttackIPDescriptorReverseIPDescriptor();
        //fill xml element
        reverseIPDescriptor.setAmountOfVirtualHosts(vhosts.size());
        for (VirtualHostname vhost : vhosts) {
            IPDescriptor.ReverseIPDescriptor.VirtualHost xmlVirtualHost = factory.createAttackIPDescriptorReverseIPDescriptorVirtualHost();
            xmlVirtualHost.setVirtualHostname(vhost.getUrl());
            reverseIPDescriptor.getVirtualHost().add(xmlVirtualHost);
        }//for
        
        //add it to ipdescr
        ipdescr.setReverseIPDescriptor(reverseIPDescriptor);
        
        //STEP-3 handle data 
        datedescriptor.setFulldate(datestr);
        String[] dateparts = datestr.split("-");
        String[] timeparts = timestr.split(",");
        datedescriptor.setYear( dateparts[0] );
        datedescriptor.setMonth( dateparts[1] );
        datedescriptor.setDay( dateparts[2] );
        datedescriptor.setTime(timeparts[0]);
        
        //STEP-4 handle malicious action
        
        //STEP-5 fill object
        attack.setIPDescriptor(ipdescr);
        attack.setDateDescriptor(datedescriptor);
        //attack.setMaliciousActionDescriptor(maliciousActionDescriptor);
        
        //STEP-6 savefile
        saveAttackFile(attack);
    }//EoM

    public static void saveAttackFile(Attack attack) {
        try {
            String filename = attack.getDateDescriptor().getYear()+"_"+attack.getDateDescriptor().getMonth()+"_"+attack.getDateDescriptor().getDay()+"_"+attack.getDateDescriptor().getTime()+"_"+attack.getIPDescriptor().getIPAddress();
            JAXBContext msjaxbContext = JAXBContext.newInstance(Attack.class);
            Marshaller msjaxbMarshaller = msjaxbContext.createMarshaller();
            msjaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

            File file = new File("output/"+filename+".xml");
            FileOutputStream fop = new FileOutputStream(file);
            msjaxbMarshaller.marshal(attack, fop);

        } catch (PropertyException ex) {
            Logger.getLogger(AttackLogParser.class.getName()).log(Level.SEVERE, null, ex);
        } catch (JAXBException ex) {
            Logger.getLogger(AttackLogParser.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(AttackLogParser.class.getName()).log(Level.SEVERE, null, ex);
        }

    }//EoM saveAttackFile

}//EoC
