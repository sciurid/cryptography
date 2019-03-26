package me.chenqiang.cert;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;

public class X500NameStructure {
	private String commonName;
	private String organizationUnit;
	private String organization;
	private String locality;
	private String stateOrProvince;
	private String country;
	
	
	
	public X500NameStructure(String commonName, String organizationUnit, String organization, String locality,
			String stateOrProvince, String country) {
		this.commonName = commonName;
		this.organizationUnit = organizationUnit;
		this.organization = organization;
		this.locality = locality;
		this.stateOrProvince = stateOrProvince;
		this.country = country;
	}
	public X500NameStructure setCommonName(String commonName) {
		this.commonName = commonName;
		return this;
	}
	public X500NameStructure setOrganizationUnit(String organizationUnit) {
		this.organizationUnit = organizationUnit;
		return this;
	}
	public X500NameStructure setOrganization(String organization) {
		this.organization = organization;
		return this;
	}
	public X500NameStructure setLocality(String locality) {
		this.locality = locality;
		return this;
	}
	public X500NameStructure setStateOrProvince(String stateOrProvince) {
		this.stateOrProvince = stateOrProvince;
		return this;
	}
	public X500NameStructure setCountry(String country) {
		this.country = country;
		return this;
	}
	
	public String toString() {
		List<String> elements = new ArrayList<String>(6);
		if(this.commonName == null) {
			elements.add(String.format("CN=%s", this.commonName));
		}
		if(this.organizationUnit == null) {
			elements.add(String.format("OU=%s", this.organizationUnit));
		}
		if(this.organization == null) {
			elements.add(String.format("O=%s", this.organization));
		}
		if(this.locality == null) {
			elements.add(String.format("L=%s", this.locality));
		}
		if(this.stateOrProvince == null) {
			elements.add(String.format("ST=%s", this.stateOrProvince));
		}
		if(this.country == null) {
			elements.add(String.format("C=%s", this.country));
		}
		return String.join(", ", elements);
	}
	
	public X500Name build() {
		return new X500Name(this.toString());
	}
	
	public static X500Name build(String commonName, String organizationUnit, String organization, String locality,
			String stateOrProvince, String country) {
		return new X500NameStructure(commonName, organizationUnit, organization,
				locality, stateOrProvince, country).build();
	}
}
