/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.ubitech.cyberattackanalyzer.RDFization;

/**
 *
 * @author eleni
 */
import com.hp.hpl.jena.datatypes.xsd.XSDDatatype;
import com.hp.hpl.jena.datatypes.xsd.XSDDateTime;
import com.hp.hpl.jena.rdf.model.Bag;
import com.hp.hpl.jena.rdf.model.Model;
import com.hp.hpl.jena.rdf.model.ModelFactory;
import com.hp.hpl.jena.rdf.model.Property;
import com.hp.hpl.jena.rdf.model.Resource;
import com.hp.hpl.jena.rdf.model.ResourceFactory;
import com.hp.hpl.jena.sparql.vocabulary.FOAF;
import com.hp.hpl.jena.vocabulary.RDF;
import com.hp.hpl.jena.vocabulary.RDFS;
import com.hp.hpl.jena.vocabulary.XSD;
import eu.ubitech.cyberattackanalyzer.model.Attack;
import eu.ubitech.cyberattackanalyzer.model.Attack.IPDescriptor.ReverseIPDescriptor.VirtualHost;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

/**
 *
 * @author eleni
 */
public class RDFMapping {

    static String cybersecurityURI = "http://www.ubitech.eu/cyberattack";
    private static final String xmlfolder = "output";
    private static final String savefolder = "rdfoutput";

    public static void main(String[] args) {

        Model model = ModelFactory.createDefaultModel();

        try {
            

            File folder = new File(xmlfolder);
            File[] listOfFiles = folder.listFiles();

            for (int i = 0; i < listOfFiles.length; i++) {
                if (listOfFiles[i].isFile() && !listOfFiles[i].getName().contains("nmap") && !listOfFiles[i].getName().contains(".directory")) {
                    System.out.println("File " + listOfFiles[i].getName());

                    String attackid = listOfFiles[i].getName().replace(".xml", "");
                    JAXBContext jaxbContext = JAXBContext.newInstance(Attack.class);
                    Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
                    
                    
                    
                    File file = new File(xmlfolder+"/"+listOfFiles[i].getName());
                    Attack attack = (Attack) jaxbUnmarshaller.unmarshal(file);

                    generateRDFModel(model, attack, attackid);

                }
            }

            exportModel(model);

        } catch (JAXBException ex) {
            Logger.getLogger(RDFMapping.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public static void generateRDFModel(Model model, Attack attack, String attackid) {

        Date date = new Date();
        DateFormat formatter = new SimpleDateFormat("ddMMyyyy");
        String today = formatter.format(date);
        String base = cybersecurityURI;

        String cyattackVocabulary = base + "#";
        String cyattack = base + "/";

        model.setNsPrefix("rdf", RDF.getURI());
        model.setNsPrefix("xsd", XSD.getURI());
        model.setNsPrefix("gn", "http://www.geonames.org/ontology#");
        model.setNsPrefix("dbo", "http://dbpedia.org/ontology#");
        model.setNsPrefix("dbp", "http://dbpedia.org/property#");
        model.setNsPrefix("geo", "http://www.w3.org/2003/01/geo/wgs84_pos#");
        model.setNsPrefix("foaf", FOAF.getURI());
        model.setNsPrefix("rdfs", RDFS.getURI());
        model.setNsPrefix("prov", "http://www.w3.org/ns/prov#");
        model.setNsPrefix("cyattack", cyattackVocabulary);

        Resource cyattack_resource = model.createResource(cyattackVocabulary + "Attack");
        Resource cyattack_statement = model.createResource(cyattack + attackid);
        cyattack_statement.addProperty(RDF.type, cyattack_resource);

        Property wasAssociatedWith = model.createProperty("http://www.w3.org/ns/prov#wasAssociatedWith");
        Resource ipdescriptor_resource = model.createResource(cyattackVocabulary + "IPDescriptor");
        Resource ipdescriptor_statement = model.createResource(cyattack + attackid + "/IPDescriptor");
        ipdescriptor_statement.addProperty(RDF.type, ipdescriptor_resource);
        Property hasIPDescriptor = model.createProperty(cyattackVocabulary + "hasIPDescriptor");
        cyattack_statement.addProperty(hasIPDescriptor, ipdescriptor_statement);

        Property hasIPAdress = model.createProperty(cyattackVocabulary + "IPAdress");

        ipdescriptor_statement.addProperty(hasIPAdress, ResourceFactory.createTypedLiteral(attack.getIPDescriptor().getIPAddress()));

        Resource locationDescriptor_resource = model.createResource(cyattackVocabulary + "LocationDescriptor");
        Resource locationDescriptor_statement = model.createResource(cyattack + attack.getIPDescriptor().getIPAddress() + "/LocationDescriptor");
        locationDescriptor_statement.addProperty(RDF.type, locationDescriptor_resource);
        Property hasLocationDescriptor = model.createProperty(cyattackVocabulary + "hasLocationDescriptor");
        ipdescriptor_statement.addProperty(hasLocationDescriptor, locationDescriptor_statement);

        Property fromcountry = model.createProperty("http://dbpedia.org/ontology#Country");
        locationDescriptor_statement.addProperty(fromcountry, ResourceFactory.createTypedLiteral(attack.getIPDescriptor().getLocationDescriptor().getCountryName().toString()));

        Property fromcity = model.createProperty("http://dbpedia.org/ontology#City");
        locationDescriptor_statement.addProperty(fromcity, ResourceFactory.createTypedLiteral(attack.getIPDescriptor().getLocationDescriptor().getCity().toString()));

        Property fromtimeZone = model.createProperty("http://dbpedia.org/ontology#timeZone");
        locationDescriptor_statement.addProperty(fromtimeZone, ResourceFactory.createTypedLiteral(attack.getIPDescriptor().getLocationDescriptor().getTimeZone().toString()));

        Property hascountryCode = model.createProperty("http://dbpedia.org/property#countryCode");
        locationDescriptor_statement.addProperty(hascountryCode, ResourceFactory.createTypedLiteral(attack.getIPDescriptor().getLocationDescriptor().getCountryCode()));

        String zipCode = attack.getIPDescriptor().getLocationDescriptor().getZipCode().toString();
        if (zipCode != null) {
            Property haszipCode = model.createProperty("http://dbpedia.org/property#zipCode");
            locationDescriptor_statement.addProperty(haszipCode, ResourceFactory.createTypedLiteral(zipCode));
        }

        Property haslatitude = model.createProperty("http://www.w3.org/2003/01/geo/wgs84_pos#lat");
        locationDescriptor_statement.addProperty(haslatitude, ResourceFactory.createTypedLiteral(Double.valueOf(attack.getIPDescriptor().getLocationDescriptor().getLatitude())));

        Property haslongitude = model.createProperty("http://www.w3.org/2003/01/geo/wgs84_pos#long");
        locationDescriptor_statement.addProperty(haslongitude, ResourceFactory.createTypedLiteral(Double.valueOf(attack.getIPDescriptor().getLocationDescriptor().getLongitude())));

        Resource blacklistingDescriptor_resource = model.createResource(cyattackVocabulary + "BlacklistingDescriptor");
        Resource blacklistingDescriptor_statement = model.createResource(cyattack + attack.getIPDescriptor().getIPAddress() + "/BlacklistingDescriptor");
        blacklistingDescriptor_statement.addProperty(RDF.type, blacklistingDescriptor_resource);
        Property hasBlacklistingDescriptor = model.createProperty(cyattackVocabulary + "hasBlacklistingDescriptor");
        ipdescriptor_statement.addProperty(hasBlacklistingDescriptor, blacklistingDescriptor_statement);

        Property hasBlacklistingLevel = model.createProperty(cyattackVocabulary + "BlacklistingLevel");
        blacklistingDescriptor_statement.addProperty(hasBlacklistingLevel, attack.getIPDescriptor().getBlacklistingDescriptor().getBlacklistingLevel());

        Resource adversaryHostDescriptor_resource = model.createResource(cyattackVocabulary + "AdversaryHostDescriptor");
        Resource adversaryHostDescriptor_statement = model.createResource(cyattack + attack.getIPDescriptor().getIPAddress() + "/AdversaryHostDescriptor");
        adversaryHostDescriptor_statement.addProperty(RDF.type, adversaryHostDescriptor_resource);
        Property hasAdversaryHostDescriptor = model.createProperty(cyattackVocabulary + "hasAdversaryHostDescriptor");
        ipdescriptor_statement.addProperty(hasAdversaryHostDescriptor, adversaryHostDescriptor_statement);

        Property hasNetworkRange = model.createProperty(cyattackVocabulary + "NetworkRange");
        adversaryHostDescriptor_statement.addProperty(hasNetworkRange, ResourceFactory.createTypedLiteral(attack.getIPDescriptor().getAdversaryHostDescriptor().getNetworkRange()));

        Property hasNetworkSize = model.createProperty(cyattackVocabulary + "NetworkSize");
        adversaryHostDescriptor_statement.addProperty(hasNetworkSize, ResourceFactory.createTypedLiteral(attack.getIPDescriptor().getAdversaryHostDescriptor().getNetworkSize()));

        Property hasNetworkName = model.createProperty(cyattackVocabulary + "NetworkName");
        adversaryHostDescriptor_statement.addProperty(hasNetworkName, ResourceFactory.createTypedLiteral(attack.getIPDescriptor().getAdversaryHostDescriptor().getNetworkName()));

        String ProvName = attack.getIPDescriptor().getAdversaryHostDescriptor().getProvName();

        if (ProvName != null) {
            Property hasProvName = model.createProperty(cyattackVocabulary + "ProvName");
            adversaryHostDescriptor_statement.addProperty(hasProvName, ResourceFactory.createTypedLiteral(attack.getIPDescriptor().getAdversaryHostDescriptor().getProvName()));

        }

        String NetworkCategory = attack.getIPDescriptor().getAdversaryHostDescriptor().getNetworkCategory();
        if (NetworkCategory != null) {
            Property hasNetworkCategory = model.createProperty(cyattackVocabulary + "NetworkCategory");
            adversaryHostDescriptor_statement.addProperty(hasNetworkCategory, ResourceFactory.createTypedLiteral(attack.getIPDescriptor().getAdversaryHostDescriptor().getNetworkCategory()));

        }

        Resource adversarySystemDescriptor_resource = model.createResource(cyattackVocabulary + "AdversarySystemDescriptor");
        Resource adversarySystemDescriptor_statement = model.createResource(cyattack + attackid + "/AdversarySystemDescriptor");
        adversarySystemDescriptor_statement.addProperty(RDF.type, adversarySystemDescriptor_resource);
        Property hasAdversarySystemDescriptor = model.createProperty(cyattackVocabulary + "hasAdversarySystemDescriptor");
        ipdescriptor_statement.addProperty(hasAdversarySystemDescriptor, adversarySystemDescriptor_statement);

        String OSDescriptor = attack.getIPDescriptor().getAdversarySystemDescriptor().getOSDescriptor();
        if (OSDescriptor != null) {
            Property hasOSDescriptor = model.createProperty(cyattackVocabulary + "OSDescriptor");
            adversarySystemDescriptor_statement.addProperty(hasOSDescriptor, ResourceFactory.createTypedLiteral(OSDescriptor));

        }

        Property hasExposedPorts = model.createProperty(cyattackVocabulary + "ExposedPorts");
        adversarySystemDescriptor_statement.addProperty(hasExposedPorts, ResourceFactory.createTypedLiteral(attack.getIPDescriptor().getAdversarySystemDescriptor().getPortsDescriptor().getAmount()));

        Resource reverseIPDescriptor_resource = model.createResource(cyattackVocabulary + "ReverseIPDescriptor");
        Resource reverseIPDescriptor_statement = model.createResource(cyattack + attackid + "/ReverseIPDescriptor");
        reverseIPDescriptor_statement.addProperty(RDF.type, reverseIPDescriptor_resource);
        Property hasReverseIPDescriptor = model.createProperty(cyattackVocabulary + "hasReverseIPDescriptor");
        ipdescriptor_statement.addProperty(hasReverseIPDescriptor, reverseIPDescriptor_statement);

        int amountofvirtualhosts = attack.getIPDescriptor().getReverseIPDescriptor().getAmountOfVirtualHosts();
        Property hasAmountOfVirtualHosts = model.createProperty(cyattackVocabulary + "AmountOfVirtualHosts");
        reverseIPDescriptor_statement.addProperty(hasAmountOfVirtualHosts, ResourceFactory.createTypedLiteral(amountofvirtualhosts));

        if (amountofvirtualhosts > 0) {

            //Resource virtualhostsbag_resource = model.createResource(cyattackVocabulary + "VirtualHostNames");
            Bag virtualhostsbag_statement = model.createBag(cyattack + attackid + "/VirtualHostNames");
            Property hasVirtualHostNames = model.createProperty(cyattackVocabulary + "hasVirtualHostNames");
            reverseIPDescriptor_statement.addProperty(hasVirtualHostNames, virtualhostsbag_statement);
            //virtualhostsbag_statement.addProperty(RDF.type, virtualhostsbag_resource);

            List<VirtualHost> virtualhosts = attack.getIPDescriptor().getReverseIPDescriptor().getVirtualHost();
            for (VirtualHost virtualhost : virtualhosts) {
                virtualhostsbag_statement.add(ResourceFactory.createTypedLiteral(virtualhost.getVirtualHostname()));
            }

        }

        Resource dateDescriptor_resource = model.createResource(cyattackVocabulary + "DateDescriptor");
        Resource dateDescriptor_statement = model.createResource(cyattack + attackid + "/DateDescriptor");
        dateDescriptor_statement.addProperty(RDF.type, dateDescriptor_resource);
        Property hasDateDescriptor = model.createProperty(cyattackVocabulary + "hasDateDescriptor");
        cyattack_statement.addProperty(hasDateDescriptor, dateDescriptor_statement);

        try {
            DateFormat df = new SimpleDateFormat("yyyy-MM-dd");
            Date fulldate;

            fulldate = df.parse(attack.getDateDescriptor().getFulldate());

            Calendar cal = Calendar.getInstance();
            cal.setTime(fulldate);

            Property hasFulldate = model.createProperty(cyattackVocabulary + "Fulldate");
            XSDDateTime dateTime = new XSDDateTime(cal);
            dateDescriptor_statement.addProperty(hasFulldate, model.createTypedLiteral(dateTime, XSDDatatype.XSDdateTime));
        } catch (ParseException ex) {
            Logger.getLogger(RDFMapping.class.getName()).log(Level.SEVERE, null, ex);
        }

        Property hasYear = model.createProperty(cyattackVocabulary + "Year");
        dateDescriptor_statement.addProperty(hasYear, ResourceFactory.createTypedLiteral(Integer.valueOf(attack.getDateDescriptor().getYear())));

        Property hasMonth = model.createProperty(cyattackVocabulary + "Month");
        dateDescriptor_statement.addProperty(hasMonth, ResourceFactory.createTypedLiteral(Integer.valueOf(attack.getDateDescriptor().getMonth())));

        Property hasDay = model.createProperty(cyattackVocabulary + "Day");
        dateDescriptor_statement.addProperty(hasDay, ResourceFactory.createTypedLiteral(Integer.valueOf(attack.getDateDescriptor().getDay())));

        Property hasTime = model.createProperty(cyattackVocabulary + "Time");
        dateDescriptor_statement.addProperty(hasTime, ResourceFactory.createTypedLiteral(attack.getDateDescriptor().getTime()));

       
    }

    public static void exportModel(Model model) {

        try {

            File file = new File(savefolder + "/outputgraph" + ".nt");
            FileWriter outToSave = null;

            outToSave = new FileWriter(file);
            model.write(outToSave, "N3");

            outToSave.close();
            System.out.println("RDF File save to:" + savefolder + "/outputgraph" + ".nt");
        } catch (IOException ex) {
            Logger.getLogger(RDFMapping.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public static void exportData(Model model, String attackid) {

        try {

            File file = new File(savefolder + "/" + attackid + ".nt");
            FileWriter outToSave = null;

            outToSave = new FileWriter(file);
            model.write(outToSave, "N3");

            outToSave.close();
            System.out.println("RDF File save to:" + savefolder + "/" + attackid + ".nt");
        } catch (IOException ex) {
            Logger.getLogger(RDFMapping.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

}
