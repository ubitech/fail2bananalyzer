//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.11 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.01.07 at 09:23:12 AM EET 
//


package eu.ubitech.cyberattackanalyzer.model;

import javax.xml.bind.annotation.XmlRegistry;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the eu.ubitech.cyberattackanalyzer.model package. 
 * <p>An ObjectFactory allows you to programatically 
 * construct new instances of the Java representation 
 * for XML content. The Java representation of XML 
 * content can consist of schema derived interfaces 
 * and classes representing the binding of schema 
 * type definitions, element declarations and model 
 * groups.  Factory methods for each of these are 
 * provided in this class.
 * 
 */
@XmlRegistry
public class ObjectFactory {


    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: eu.ubitech.cyberattackanalyzer.model
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link Attack }
     * 
     */
    public Attack createAttack() {
        return new Attack();
    }

    /**
     * Create an instance of {@link Attack.IPDescriptor }
     * 
     */
    public Attack.IPDescriptor createAttackIPDescriptor() {
        return new Attack.IPDescriptor();
    }

    /**
     * Create an instance of {@link Attack.IPDescriptor.ReverseIPDescriptor }
     * 
     */
    public Attack.IPDescriptor.ReverseIPDescriptor createAttackIPDescriptorReverseIPDescriptor() {
        return new Attack.IPDescriptor.ReverseIPDescriptor();
    }

    /**
     * Create an instance of {@link Attack.IPDescriptor.AdversarySystemDescriptor }
     * 
     */
    public Attack.IPDescriptor.AdversarySystemDescriptor createAttackIPDescriptorAdversarySystemDescriptor() {
        return new Attack.IPDescriptor.AdversarySystemDescriptor();
    }

    /**
     * Create an instance of {@link Attack.IPDescriptor.AdversarySystemDescriptor.PortsDescriptor }
     * 
     */
    public Attack.IPDescriptor.AdversarySystemDescriptor.PortsDescriptor createAttackIPDescriptorAdversarySystemDescriptorPortsDescriptor() {
        return new Attack.IPDescriptor.AdversarySystemDescriptor.PortsDescriptor();
    }

    /**
     * Create an instance of {@link Attack.DateDescriptor }
     * 
     */
    public Attack.DateDescriptor createAttackDateDescriptor() {
        return new Attack.DateDescriptor();
    }

    /**
     * Create an instance of {@link Attack.MaliciousActionDescriptor }
     * 
     */
    public Attack.MaliciousActionDescriptor createAttackMaliciousActionDescriptor() {
        return new Attack.MaliciousActionDescriptor();
    }

    /**
     * Create an instance of {@link Attack.IPDescriptor.LocationDescriptor }
     * 
     */
    public Attack.IPDescriptor.LocationDescriptor createAttackIPDescriptorLocationDescriptor() {
        return new Attack.IPDescriptor.LocationDescriptor();
    }

    /**
     * Create an instance of {@link Attack.IPDescriptor.BlacklistingDescriptor }
     * 
     */
    public Attack.IPDescriptor.BlacklistingDescriptor createAttackIPDescriptorBlacklistingDescriptor() {
        return new Attack.IPDescriptor.BlacklistingDescriptor();
    }

    /**
     * Create an instance of {@link Attack.IPDescriptor.AdversaryHostDescriptor }
     * 
     */
    public Attack.IPDescriptor.AdversaryHostDescriptor createAttackIPDescriptorAdversaryHostDescriptor() {
        return new Attack.IPDescriptor.AdversaryHostDescriptor();
    }

    /**
     * Create an instance of {@link Attack.IPDescriptor.ReverseIPDescriptor.VirtualHost }
     * 
     */
    public Attack.IPDescriptor.ReverseIPDescriptor.VirtualHost createAttackIPDescriptorReverseIPDescriptorVirtualHost() {
        return new Attack.IPDescriptor.ReverseIPDescriptor.VirtualHost();
    }

    /**
     * Create an instance of {@link Attack.IPDescriptor.AdversarySystemDescriptor.OSDescriptor }
     * 
     */
    public Attack.IPDescriptor.AdversarySystemDescriptor.OSDescriptor createAttackIPDescriptorAdversarySystemDescriptorOSDescriptor() {
        return new Attack.IPDescriptor.AdversarySystemDescriptor.OSDescriptor();
    }

    /**
     * Create an instance of {@link Attack.IPDescriptor.AdversarySystemDescriptor.PortsDescriptor.PortDescriptor }
     * 
     */
    public Attack.IPDescriptor.AdversarySystemDescriptor.PortsDescriptor.PortDescriptor createAttackIPDescriptorAdversarySystemDescriptorPortsDescriptorPortDescriptor() {
        return new Attack.IPDescriptor.AdversarySystemDescriptor.PortsDescriptor.PortDescriptor();
    }

}
