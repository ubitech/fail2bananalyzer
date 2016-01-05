/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.ubitech.cyberattackanalyzer.service.location;

/**
 *
 * @author vmadmin
 */
public interface ILocationRetriever {
    
    public String inferLocation(String ipaddress);
    
}
