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
package eu.ubitech.cyberattackanalyzer.service.location;

/**
 *
 * @author Panagiotis Gouvas (pgouvas@ubitech.eu)
 */
public class Location {
        //IP
        private String IP;
        //CountryCode
        private String CountryCode;
        //CountryName
        private String CountryName;        
        //RegionCode
        private String RegionCode;             
        //RegionName
        private String RegionName;                     
        //City
        private String City;                     
        //ZipCode
        private String ZipCode;                     
        //TimeZone
        private String TimeZone;                     
        //Latitude
        private String Latitude;                     
        //Longitude
        private String Longitude;                     
        //MetroCode
        private String MetroCode;     

    public String getIP() {
        return IP;
    }

    public void setIP(String IP) {
        this.IP = IP;
    }

    public String getCountryCode() {
        return CountryCode;
    }

    public void setCountryCode(String CountryCode) {
        this.CountryCode = CountryCode;
    }

    public String getCountryName() {
        return CountryName;
    }

    public void setCountryName(String CountryName) {
        this.CountryName = CountryName;
    }

    public String getRegionCode() {
        return RegionCode;
    }

    public void setRegionCode(String RegionCode) {
        this.RegionCode = RegionCode;
    }

    public String getRegionName() {
        return RegionName;
    }

    public void setRegionName(String RegionName) {
        this.RegionName = RegionName;
    }

    public String getCity() {
        return City;
    }

    public void setCity(String City) {
        this.City = City;
    }

    public String getZipCode() {
        return ZipCode;
    }

    public void setZipCode(String ZipCode) {
        this.ZipCode = ZipCode;
    }

    public String getTimeZone() {
        return TimeZone;
    }

    public void setTimeZone(String TimeZone) {
        this.TimeZone = TimeZone;
    }

    public String getLatitude() {
        return Latitude;
    }

    public void setLatitude(String Latitude) {
        this.Latitude = Latitude;
    }

    public String getLongitude() {
        return Longitude;
    }

    public void setLongitude(String Longitude) {
        this.Longitude = Longitude;
    }

    public String getMetroCode() {
        return MetroCode;
    }

    public void setMetroCode(String MetroCode) {
        this.MetroCode = MetroCode;
    }
            
        
}
