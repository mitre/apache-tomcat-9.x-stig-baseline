control 'SV-222966' do
  title 'DOD root CA certificates must be installed in Tomcat trust store.'
  desc 'Tomcat truststores are used to validate client certificates. On the Ubuntu OS, by default, Tomcat uses the "cacerts" file as the CA trust store. The file is located in the /etc/ssl/certs/java/ folder with a link to the file in $JAVA_HOME/lib/security/cacerts. However, this location can be modified by setting the value of the javax.net.ssl.trustStore system property. Setting this property within an OS environment variable will change the location to point to a different trust store. 

The Java OS environment variables in the systemd Tomcat startup file must be checked in order to identify the location of the trust store on the file system. (The STIG uses the name tomcat.service as a reference, but technically this file can be called anything).

If the property is not set, then the default location is used for the truststore.'
  desc 'check', 'This is a mutual authentication requirement where both the Tomcat server and the client are required to authenticate themselves via mutual TLS. Review system security plan and other system documentation. If the system has no connections requiring mutual authentication (e.g., proxy servers or other hosts specified in the system documentation), this requirement is Not Applicable.

For the systemd Ubuntu OS, check the tomcat.service file to read the content of the JAVA_OPTS environment variable setting.

sudo cat /etc/systemd/system/tomcat.service |grep -i truststore

EXAMPLE output:
set JAVA_OPTS="-Djavax.net.ssl.trustStore=/path/to/truststore" "-Djavax.net.ssl.trustStorePassword=************"

If the variable is not set, use the default location command below. If the variable is set, use the alternate location command below and include the path and truststore file. 

-Default location:
keytool -list -cacerts -v | grep -i issuer

-Alternate location:
keytool -list -keystore <location of trust store file> -v |grep -i issuer

If there are no CA certificates issued by a CA that are part of the DOD PKI/PKE, this is a finding.'
  desc 'fix', 'Obtain and install the DOD PKI CA certificate bundles by accessing the DOD PKI office website at cyber.mil/pki-pke.

Import the DOD CA certificates.'
  impact 0.5
  tag check_id: 'C-24638r985889_chk'
  tag severity: 'medium'
  tag gid: 'V-222966'
  tag rid: 'SV-222966r985891_rule'
  tag stig_id: 'TCAT-AS-000700'
  tag gtitle: 'SRG-APP-000175-AS-000124'
  tag fix_id: 'F-24627r985890_fix'
  tag 'documentable'
  tag legacy: ['SV-111457', 'V-102515']
  tag cci: ['CCI-000185', 'CCI-004909']
  tag nist: ['IA-5 (2) (b) (1)', 'SC-17 b']

  describe 'This is a manual check' do
    skip 'Check the truststore settings in the tomcat.service file. If the variable is not set then run the command:
    \'keytool -list -cacerts -v | grep -i issuer\' if the variable is already set then add an alternate location with the
    command: \'keytool -list -keystore <location of trust store file> -v | grep -i issuer\''
  end
end
