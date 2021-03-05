Electronic Vaccination Proof specification version 0.1.0, 2021-02-24.


# Abstract

This document specifies a data structure and encoding mechanisms for vaccination proofs to be used cross-border. It also specifies a transport encoding mechanism in a machine-readable optical format (Aztec), which can be displayed on the screen of a mobile device or printed on a piece of paper.


# Terminology

Organisations adopting this specification for issuing vaccination passes are called Issuers and organisations accepting vaccination passes as proof of vaccination is called Verifiers. Together, these are called Participants. Some aspects in this document must be coordinated between the Participants, such as the management of a name space and the distribution of cryptographic keys. It is assumed that a party, hereafter referred to as the Coordinator, carries out these tasks. The vaccination pass format of this specification is called the Electronic Vaccination Proof, hereafter referred to as the EVP.

The keywords "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT", "RECOMMENDED" and "MAY" should be interpreted as described in (RFC 2119).


## Versioning policy

Versions of this specification consist of three different integers describing the *major*, *minor* and *edition* version. 

A change in the *major* version is an update that includes material changes affecting the decoding of the EVP or the validation of it.
 
An update of the *minor* version is a feature or maintenance update that maintains backward compatibility with previous versions.

In addition, there is an *edition* version number used for publishing updates to the document itself which have no effect on the EVP, such as correcting spelling, providing clarifications or addressing ambiguities, et cetera. Hence, the edition number is not indicated in the EVP. The version numbers are expressed in the title page of the document using a *major.minor.edition* format, where the three parts are separated by decimal dots. 

In the EVP, The *major* and *minor* versions are indicated in the Issuer Protected Header of the EVP.


# Electronic Vaccination Proof

The Electronic Vaccination Proof (EVP) is designed to provide a uniform and standardised vehicle for vaccination proofs from different Issuers. The aim is to harmonise how vaccination passes are represented, encoded and signed with the goal of facilitating interoperability, while protecting the holder's personal integrity and minimise costs in implementation.


## Coordinated Data Structure

Ability to read and interpret EVPs issued by any Issuer requires a common data structure and agreements of the significance of each data field. To facilitate such interoperability, a common coordinated data structure is defined through the use of a JSON schema, Appendix A. Critical elements of a vaccination pass SHOULD use this data structure. A Participant MAY extend the objects with proprietary data. The naming of such objects MUST be agreed between all Participants.


## Structure of the Electronic Vaccination Proof

The EVP consists of these basic parts:

- Issuer Protected Header
- Payload (Coordinated Data Structure)
- Issuer Signature

The Issuer Signature is used for integrity protection and data origin authentication of the Issuer Protected Header and the Payload information.


## Payload

The EVP is represented using CBOR Web Token (CWT) as defined [RFC 8392](https://tools.ietf.org/html/rfc8392). The EVP payload is transported in a HEALTHPASS claim (value type TBD).

Strings SHOULD be NFC normalised according to the Unicode standard. Decoding applications SHOULD however be permissive and robust in these aspects, and acceptance of any reasonable type conversion is strongly encouraged. If unnormalised data is found during decoding, or in subsequent comparison function, implementations SHOULD behave as if the input is normalised to NFC.

The integrity and authenticity of origin of data contained both within the Payload and the Issuer Protected Header MUST be verifiable by the Verifier. To provide this mechanism, the issuer of the EVP MUST sign the Payload using an asymmetric electronic signature scheme as defined in the COSE specification (RFC 8152). This forms the Issuer Signed Payload.


## Issuer Protected Header

An Issuer Protected Header object that provides the required metadata for the signature SHALL be attached to the Payload as defined by the COSE specification. The Issuer Signature Protected Header SHALL include the following parameters:

- **iid**: Issuer Identifier (bstr)
- **kid**: Issuer Key identifier (bstr)
- **exp**: Issuer Signature Expiry (timestamp in ISO 8601 basic format, bstr)
- **ver**: EVP Specification version (bstr)

The Verifier SHALL validate the Issuer Signature before any further processing of any of the information of the Payload.

(NOTE: In this draft, all but the kid parameter are using private COSE header parameter labels)


### Issuer Identifier

The Issuer Identifier (**iid**) parameter holds the identifier of the entity issuing the EVP. The namespace of the Issuer Identifiers MUST be agreed between the Participants, but is not defined in the specification. The **iid** SHALL be encoded using COSE header parameter label -100000 (decimal).


### Issuer Key Identifier

The Issuer Key Identifier (**kid**) parameter is used by Verifiers for selecting the correct public key from a list of keys pertaining to the Issuer specified by the Issuer Identifier. Several keys may be used in parallel for administrative reasons and when performing key rollovers. Key Identifiers are selected by the responsible Issuer and is REQUIRED to be unique per Issuer.


### Issuer Signature Expiry

The Issuer Signature Expiry (**exp**) timestamp is used to indicate for how long this particular signature over the Payload SHALL be considered valid, after which a Verifier MUST reject the Payload as expired. The timestamp MUST be given in UTC. The purpose of the expiry parameter is to force a limit of the validity period of the EVP. The **exp** SHALL be encoded using COSE header parameter label -100001 (decimal).


### EVP Specification Version

The EVP Specification Version (**ver**) indicates to which version of this specification the Payload adheres. The version numbers are encoded as a string using the *major.minor* format, where the major number and minor number are separated by a decimal dot. The **evp** SHALL be encoded using COSE header parameter label -100002 (decimal).

## Issuer Signature

For the Issuer Signature, one primary and one fallback algorithm is defined. The fallback algorithm is only used in the unlikely event the cryptographic strength of the primary algorithm becomes insufficient in providing reliable data integrity protection and origin authentication among the Participants. However, it is essential and of utmost importance for the security of the system that all implementations incorporate the fallback algorithm. For this reason, both the primary and the fallback algorithm MUST be implemented.

- **Primary Algorithm** The primary algorithm is Elliptic Curve Digital Signature Algorithm (ECDSA) as defined in (ISO/IEC 14888-3:2006) section 2.3, using the P-256 parameters as defined in appendix D (D.1.2.3) of (FIPS PUB 186-4) in combination the SHA-256 hash algorithm as defined in (ISO/IEC 10118-3:2004) function 4.

This corresponds to the COSE algorithm parameter **ES256**.

- **Fallback Algorithm** The fallback algorithm is RSASSA-PKCS#1 v1.5 as defined in (RFC 3447) with a modulus of 2048 bits in combination with the SHA-256 hash algorithm as defined in (ISO/IEC 10118-3:2004) function 4.

This corresponds to the COSE algorithm parameter: **RS256**


## Data compression

To improve speed and reliability in the reading process of the EVP, the Issuer Signed Payload SHALL be compressed using ZLIB (RFC 1950) and the Deflate compression mechanism in the format defined in (RFC 1951).


# Transport Encodings

## Raw

For arbitrary data interfaces the EVP may be transferred as-is, utilising any underlying reliable data transport. These interfaces MAY include NFC, Bluetooth or transfer over an application layer protocol, for example transfer of an EVP from the Issuer to a holder's mobile device.

If the transfer of the EVP from the Issuer to the holder is based on a presentation-only interface (e.g., SMS, e-mail), the Raw transport encoding is obviously not applicable.


## AZTEC 2D Barcode

To optically represent the EVP using a compact machine-readable format the Aztec 2D Barcode (ISO/IEC 24778:2008) SHALL be used. 
When generating the optical code an error correction rate of 23% is RECOMMENDED. The optical code is RECOMMENDED to be rendered on the presentation media with a diagonal size between 35 mm and 65 mm. 


# Security Considerations

When designing a scheme using this specification, several important security aspects must be considered. These can not preemptively be accounted for in this specification, but must be identified, analysed and monitored by the Participants.

As input to the continuous analysis and monitoring of risks, the following topics SHOULD be taken into account:

## EVP Validity Time

It is anticipated that EVPs can not be reliably revoked once issued, especially not if this specification would be used on a global scale. Mainly for this reason, this specification requires the Issuer of an EVP to limit the EVP's validity period by specifying an expiry time. This requires to holder of an EVP to renew the EVP on some regular basis. 

The acceptable validity period would be determined by practical constraints, a traveller may not have the possibility to renew the EVP during a travel overseas. But it may also be that an Issuer of EVP's are considering the possibility of a security compromise of some sort, which requires the Issuer to withdraw an Issuer Key (invalidating all EVPs signed using that key). The consequences of such an event may be limited by regularly rolling Issuer keys and requiring renewal of all EVPs, on some reasonable interval.


## Key management

This specification relies heavily on strong cryptographic mechanisms to secure data integrity and data origin authentication. Maintaining the confidentiality of the private encryption keys are therefor of utmost importance.

The confidentiality of cryptographic keys can be compromised in a number of different ways, for instance;

- The key generation process may be flawed, resulting in weak keys.
- The keys may be exposed by human error.
- The keys may be stolen by external or internal perpetrators.
- The keys may be calculated using cryptanalysis.

To mitigate against the risks that the signing algorithm is found to be weak, allowing the private keys to be compromised through cryptanalysis, this specification recommends all Participants to implement a fallback signature algorithm based on different parameters or a different mathematical problem than the primary.

The other risks mentioned here are related to the Issuers' operating environments. One effective control to mitigate significant parts of these risks is to generate, store and use the private keys in Hardware Security Modules (HSMs). Use of HSMs for signing EVPs is highly encouraged.

However, regardless if an Issuer decides to use HSMs or not, a key roll-over schedule SHOULD be established where the frequency of the key roll-overs is proportionate to the exposure of keys to external networks, other systems and personnel. A well-chosen roll-over schedule also limits the risks associated with erroneously issued EVPs, enabling an Issuer to revoke such EVPs in batches, by withdrawing a key, if required.


## Input data validation

This specification may be used in a way which implies receiving data from untrusted sources into systems which may be of mission-critical nature. To minimise the risks associated with this attack vector, all input fields MUST be properly validated by data types, lengths and contents. The Issuer Signature SHALL also be verified before any processing of the contents of the EVP takes place. However, the validation of the Issuer Signature implies parsing the Protected Issuer Header first, in which a potential attacker may attempt to inject carefully crafted information designed to compromise the security of the system.



# Appendix A

([vproof_schema](https://raw.githubusercontent.com/kirei/vproof/main/vproof_schema.yaml))

_________________

Fredrik Ljunggren, Kirei AB.

Shield: [![CC BY 4.0][cc-by-shield]][cc-by]

This work is licensed under a
[Creative Commons Attribution 4.0 International License][cc-by].

[![CC BY 4.0][cc-by-image]][cc-by]

[cc-by]: http://creativecommons.org/licenses/by/4.0/
[cc-by-image]: https://i.creativecommons.org/l/by/4.0/88x31.png
[cc-by-shield]: https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg
