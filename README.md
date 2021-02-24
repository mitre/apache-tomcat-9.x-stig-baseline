## Apache Tomcat STIG Automated Compliance Validation Profile
<b>Apache Tomcat 9.X</b>

<b>Apache Tomcat 9.X</b> STIG Automated Compliance Validation Profile works with Chef InSpec to perform automated compliance checks of <b>Apache Tomcat</b>.

This automated Security Technical Implementation Guide (STIG) validator was developed to reduce the time it takes to perform a security check based upon STIG Guidance from DISA. These check results should provide information needed to receive a secure authority to operate (ATO) certification for the applicable technology.
<b>Apache Tomcat</b> uses [Chef InSpec](https://github.com/chef/inspec), which provides an open source compliance, security and policy testing framework that dynamically extracts system configuration information.

## Apache Tomcat STIG Overview

The <b>Apache Tomcat</b> STIG (https://public.cyber.mil/stigs/) by the United States Defense Information Systems Agency (DISA) offers a comprehensive compliance guide for the configuration and operation of various technologies.
DISA has created and maintains a set of security guidelines for applications, computer systems or networks connected to the DoD. These guidelines are the primary security standards used by many DoD agencies. In addition to defining security guidelines, the STIG also stipulates how security training should proceed and when security checks should occur. Organizations must stay compliant with these guidelines or they risk having their access to the DoD terminated.

[STIG](https://en.wikipedia.org/wiki/Security_Technical_Implementation_Guide)s are the configuration standards for United States Department of Defense (DoD) Information Assurance (IA) and IA-enabled devices/systems published by the United States Defense Information Systems Agency (DISA). Since 1998, DISA has played a critical role enhancing the security posture of DoD's security systems by providing the STIGs. The STIGs contain technical guidance to "lock down" information systems/software that might otherwise be vulnerable to a malicious computer attack.

The requirements associated with the <b>Apache Tomcat</b> STIG are derived from the [National Institute of Standards and Technology](https://en.wikipedia.org/wiki/National_Institute_of_Standards_and_Technology) (NIST) [Special Publication (SP) 800-53, Revision 4](https://en.wikipedia.org/wiki/NIST_Special_Publication_800-53) and related documents.

While the Apache Tomcat STIG automation profile check was developed to provide technical guidance to validate information with security systems such as applications, the guidance applies to all organizations that need to meet internal security as well as compliance standards.

### This STIG Automated Compliance Validation Profile was developed based upon:
- Apache Tomcat Security Technical Implementation Guide
### Update History 
| Guidance Name  | Guidance Version | Guidance Location                            | Profile Version | Profile Release Date | STIG EOL    | Profile EOL |
|---------------------------------------|------------------|--------------------------------------------|-----------------|----------------------|-------------|-------------|
| Apache Tomcat 9.x STIG  | Ver 2, Rel 1    | https://public.cyber.mil/stigs/downloads/  |           |       | NA | NA |

## Getting Started

### Requirements

#### Apache Tomcat  
- Apache Tomcat Server
- Access to the Apache Tomcat Application Server
- Account providing appropriate permissions to perform audit scan


#### Required software on Apache Tomcat Application Server
- git
- [InSpec](https://www.chef.io/products/chef-inspec/)

### Setup Environment on Apache Tomcat Application Server 
#### Install InSpec
Goto https://www.inspec.io/downloads/ and consult the documentation for your Operating System to download and install InSpec.

#### Ensure InSpec version is at least 4.23.10 
```sh
inspec --version
```

<<<<<<< HEAD
### How to execute this instance  
(See: https://www.inspec.io/docs/reference/cli/)

#### Execute a single Control in the Profile 
**Note**: Replace the profile's directory name - e.g. - `<Profile>` with `.` if currently in the profile's root directory.
```sh
inspec exec <Profile>/controls/V-102427.rb --show-progress
```
or use the --controls flag to execute checking with a subset of controls
```sh
inspec exec <Profile> --controls=V-102427.rb V-102427.rb --show-progress
```

#### Execute a Single Control and save results as JSON 
```sh
inspec exec <Profile> --controls=V-102427.rb --show-progress --reporter json:results.json
```

#### Execute All Controls in the Profile 
```sh
inspec exec <Profile> --show-progress
```

#### Execute all the Controls in the Profile and save results as JSON 
```sh
inspec exec <Profile> --show-progress  --reporter json:results.json
```

## Check Overview

**Manual Checks**

These checks are not included in the automation process.

| Control Number | Description                                                                                                   |
|----------------|---------------------------------------------------------------------------------------------------------------------------------|
| V-102427       | The number of allowed simultaneous sessions to the manager application must be limited.                                         |
| V-102429       | Secured connectors must be configured to use strong encryption ciphers.                                                         |
| V-102445       | Default password for keystore must be changed.                                                                                  |
| V-102451       | DefaultServlet must be set to readonly for PUT and DELETE.                                                                      |
| V-102457       | Tomcat servers behind a proxy or load balancer must log client IP.                                                              |
| V-102487       | Unapproved connectors must be disabled.                                                                                         |
| V-102501       | Tomcat default ROOT web application must be removed.                                                                            |
| V-102515       | DoD root CA certificates must be installed in Tomcat trust store.                                                               |
| V-102517       | Keystore file must be protected.                                                                                                |
| V-102521       | Access to JMX management interface must be restricted.                                                                          |
| V-102523       | Access to Tomcat manager application must be restricted.                                                                        |
| V-102525       | Tomcat servers must mutually authenticate proxy or load balancer connections.                                                   |
| V-102531       | Clusters must operate on a trusted network.                                                                                     |
| V-102535       | Default error pages for manager application must be customized.                                                                 |
| V-102539       | Tomcat server version must not be sent with warnings and errors.                                                                |
| V-102551       | Tomcat user account must be a non-privileged user.                                                                              |
| V-102569       | Multifactor certificate-based tokens (CAC) must be used when accessing the management interface.                                |
| V-102571       | Certificates in the trust store must be issued/signed by an approved CA.                                                        |
| V-102573       | The application server, when categorized as a high availability system within RMF, must be in a high-availability (HA) cluster. |
| V-102575       | Tomcat server must be patched for security vulnerabilities.                                                                     |
| V-102579       | Changes to $CATALINA_HOME/bin/ folder must be logged.                                                                           |
| V-102581       | Changes to $CATALINA_BASE/conf/ folder must be logged.                                                                          |
| V-102583       | Changes to $CATALINA_HOME/lib/ folder must be logged.                                                                           |
| V-102585       | Application servers must use NIST-approved or NSA-approved key management technology and processes.                             |
| V-102595       | Tomcat users in a management role must be approved by the ISSO.                                                                 |
| V-102597       | Hosted applications must be documented in the system security plan.                                                             |
| V-102599       | Connectors must be approved by the ISSO.                                                                                        |
| V-102601       | Connector address attribute must be set.                                                                                        |
| V-102621       | The application server must alert the SA and ISSO, at a minimum, in the event of a log processing failure.                      |

**Normal Checks**

These checks will follow the normal automation process and will report accurate STIG compliance PASS/FAIL.

| Control Number | Description                                                                                  |
|----------------|----------------------------------------------------------------------------------------------|
| V-102431       | HTTP Strict Transport Security (HSTS) must be enabled.                                       |
| V-102433       | TLS 1.2 must be used on secured HTTP connectors.                                             |
| V-102435       | AccessLogValve must be configured for each application context.                              |
| V-102447       | Cookies must have secure flag set.                                                           |
| V-102449       | Cookies must have http-only flag set.                                                        |
| V-102453       | Connectors must be secured.                                                                  |
| V-102455       | The Java Security Manager must be enabled.                                                   |
| V-102461       | Date and time of events must be logged.                                                      |
| V-102463       | Remote hostname must be logged.                                                              |
| V-102465       | HTTP status code must be logged.                                                             |
| V-102467       | The first line of request must be logged.                                                    |
| V-102469       | $CATALINA_BASE/logs folder permissions must be set to 750.                                   |
| V-102471       | Files in the $CATALINA_BASE/logs/ folder must have their permissions set to 640.             |
| V-102473       | Files in the $CATALINA_BASE/conf/ folder must have their permissions set to 640.             |
| V-102477       | Jar files in the $CATALINA_HOME/bin/ folder must have their permissions set to 640.          |
| V-102481       | Tomcat user UMASK must be set to 0027.                                                       |
| V-102483       | Stack tracing must be disabled.                                                              |
| V-102485       | The shutdown port must be disabled.                                                          |
| V-102489       | DefaultServlet debug parameter must be disabled.                                             |
| V-102491       | DefaultServlet directory listings parameter must be disabled.                                |
| V-102493       | The deployXML attribute must be set to false in hosted environments.                         |
| V-102495       | Autodeploy must be disabled.                                                                 |
| V-102497       | xpoweredBy attribute must be disabled.                                                       |
| V-102499       | Example applications must be removed.                                                        |
| V-102503       | Documentation must be removed.                                                               |
| V-102505       | Applications in privileged mode must be approved by the ISSO.                                |
| V-102507       | Tomcat management applications must use LDAP realm authentication.                           |
| V-102509       | JMX authentication must be secured.                                                          |
| V-102511       | TLS must be enabled on JMX.                                                                  |
| V-102513       | LDAP authentication must be secured.                                                         |
| V-102527       | Idle timeout for management application must be set to 10 minutes.                           |
| V-102529       | Tomcat must be configured to limit data exposure between applications.                       |
| V-102533       | ErrorReportValve showServerInfo must be set to false.                                        |
| V-102537       | ErrorReportValve showReport must be set to false.                                            |
| V-102541       | Idle timeout for management application must be set to 10 minutes.                           |
| V-102543       | LockOutRealms must be used for management of Tomcat.                                         |
| V-102545       | LockOutRealms failureCount attribute must be set to 5 failed logins for admin users.         |
| V-102547       | LockOutRealms lockOutTime attribute must be set to 600 seconds (10 minutes) for admin users. |
| V-102549       | Tomcat user account must be set to nologin.                                                  |
| V-102553       | Application user name must be logged.                                                        |
| V-102555       | $CATALINA_HOME folder must be owned by the root user, group tomcat.                          |
| V-102557       | $CATALINA_BASE/conf/ folder must be owned by root, group tomcat.                             |
| V-102559       | $CATALINA_BASE/logs/ folder must be owned by tomcat user, group tomcat.                      |
| V-102561       | $CATALINA_BASE/temp/ folder must be owned by tomcat user, group tomcat.                      |
| V-102563       | $CATALINA_BASE/temp folder permissions must be set to 750.                                   |
| V-102565       | $CATALINA_BASE/work/ folder must be owned by tomcat user, group tomcat.                      |
| V-102567       | Idle timeout for management application must be set to 10 minutes.                           |
| V-102577       | AccessLogValve must be configured for Catalina engine.                                       |
| V-102587       | STRICT_SERVLET_COMPLIANCE must be set to true.                                               |
| V-102589       | RECYCLE_FACADES must be set to true.                                                         |
| V-102591       | ALLOW_BACKSLASH must be set to false.                                                        |
| V-102593       | ENFORCE_ENCODING_IN_GET_WRITER must be set to true.                                          |
| V-102603       | AccessLogValve must be configured per each virtual host.                                     |
| V-102605       | $CATALINA_BASE/conf folder permissions must be set to 750.                                   |
| V-102607       | $CATALINA_HOME/bin folder permissions must be set to 750.                                    |
| V-102609       | Tomcat must use FIPS-validated ciphers on secured connectors.                                |

## Authors

Defense Information Systems Agency (DISA) https://www.disa.mil/

STIG support by DISA Risk Management Team and Cyber Exchange https://public.cyber.mil/

## Legal Notices

Copyright © 2020 Defense Information Systems Agency (DISA)
