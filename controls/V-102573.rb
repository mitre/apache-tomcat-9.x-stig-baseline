control 'V-102573' do
  title "The application server, when categorized as a high availability system
within RMF, must be in a high-availability (HA) cluster."
  desc  "A MAC I system is a system that handles data vital to the
organization's operational readiness or effectiveness of deployed or
contingency forces. A MAC I system must maintain the highest level of integrity
and availability. By HA clustering the application server, the hosted
application and data are given a platform that is load-balanced and provided
high-availability."
  desc  'rationale', ''
  desc  'check', "
    This requirement only applies to a system that is categorized as high
within the Risk Management Framework (RMF).

    Review the System Security Plan (SSP) or other system documentation that
specifies the operational uptime requirements and RMF system categorization.

    If the system is categorized as high, from the Tomcat server as a
privileged user, run the following command:

    sudo grep -i -A10 -B2 \"Cluster\" $CATALINA_BASE/conf/server.xml

    If the <Cluster/> element is commented out, or no results returned, then
the system is not clustered and this is a finding.This requirement only applies to a system that is categorized as high
within the Risk Management Framework (RMF).

    Review the System Security Plan (SSP) or other system documentation that
specifies the operational uptime requirements and RMF system categorization.

    If the system is categorized as high, from the Tomcat server as a
privileged user, run the following command:

    sudo grep -i -A10 -B2 \"Cluster\" $CATALINA_BASE/conf/server.xml

    If the <Cluster/> element is commented out, or no results returned, then
the system is not clustered and this is a finding.
  "
  desc 'fix', "
    From the Tomcat server as a privileged user, modify the
$CATALINA_BASE/conf/server.xml file.

    Uncomment the \"<Cluster/> object and configure the system into a cluster
as per the Tomcat clustering documentation provided at the Tomcat website.

    https://tomcat.apache.org/tomcat-9.0-doc/config/cluster.html
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000435-AS-000069'
  tag gid: 'V-102573'
  tag rid: 'SV-111513r1_rule'
  tag stig_id: 'TCAT-AS-001460'
  tag fix_id: 'F-108105r1_fix'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5']

  if !input('system_categorization').downcase == 'high'
    impact 0.0
    desc 'caveat', 'This requirement not applicable to the system since it is not categorized as high'
  else
    catalina_base = input('catalina_base')
    tomcat_server_file = xml("#{catalina_base}/conf/server.xml")

    describe 'The system should apart of a server cluster' do
      subject { tomcat_server_file['//Cluster'] }
      it { should_not be_empty }
    end
  end
end
