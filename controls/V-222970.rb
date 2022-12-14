control 'V-222970' do
  title 'Access to Tomcat manager application must be restricted.'
  desc '
  The Tomcat manager application is used to manage the Tomcat server and the
    applications that run on Tomcat. By default, the manager application is
    only accessible via the localhost. Exposing the management application to
    any network interface that is available to non-administrative personnel
    leaves the Tomcat server vulnerable to attempts to access the management
    application. To mitigate this risk, the management application should only
    be run on the localhost or on network interfaces tied to a dedicated
    management network.

  This setting is managed in the $CATALINA_BASE/conf/server.xml file.
  '
  desc 'rationale', ''

  desc 'check', '
  Review system documentation (SSP) and identify the documented management
    networks as well as the documented client networks. If the manager
    application has been deleted from the system, this is not a finding.

  Run the following command as a privileged user:

  sudo grep -i -A1 "RemoteAddrValve\\|RemoteCIDRValve"
    $CATALINA_BASE/webapps/manager/META-INF/context.xml

  If there are no results, then no address valves exist and this is a
    finding.

  If the Remote Address Valve settings are commented out or not configured to
    restrict access to localhost or the management network, this is a finding.

  EXAMPLES:

  - RemoteAddrValve Localhost only IPV4 and IPV6 example
  <Valve className="org.apache.catalina.valves.RemoteAddrValve"
     allow="127\\.\\d+\\.\\d+\\.\\d+|::1|0:0:0:0:0:0:0:1"/>

  - Localhost and Management network CIDR block IPV4 and IPV6 example
  <Valve className="org.apache.catalina.valves.RemoteCIDRValve"
  allow="127.0.0.1, ::1",192.168.1.0/24/>
  '
  desc 'fix', '
  Update system documentation (SSP) and identify the documented management
    networks as well as the documented client networks.

  As a privileged user, edit the $CATALINA_BASE/webapps/manager/META-
    INF/context.xml file.

  Configure the RemoteAddrValve or RemoteCIDRValve to restrict access to the
    management application. This can be a restriction to the localhost or to
    specific management networks or hosts on the management network. Choice of
    address or CIDR block usage is based on operational requirements.

  Order is allow from, deny from. See Tomcat Valve component documentation at
    the Tomcat website for specific details and additional configuration
    options.

  Test the access restrictions once configured to assure compliance.

  EXAMPLES:

  - RemoteAddrValve Localhost only IPV4 and IPV6
  <Valve className="org.apache.catalina.valves.RemoteAddrValve"
     allow="127\\.\\d+\\.\\d+\\.\\d+|::1|0:0:0:0:0:0:0:1"/>

  - Localhost and Management network CIDR block IPV4 and IPV6
  <Valve className="org.apache.catalina.valves.RemoteCIDRValve"
  allow="127.0.0.1, ::1",192.168.1.0/24/>
  '

  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-AS-000146'
  tag gid: 'V-222970'
  tag rid: 'SV-222970r615938_rule'
  tag stig_id: 'TCAT-AS-000790'
  tag fix_id: 'F-24631r426355_fix'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']

  if !input('manager_app_installed')
    impact 0.0
    desc 'caveat', 'The maanger application is not installed. This is not a finding.'

    describe 'Manager application is not installed' do
      skip 'Manager application is not installed. This is not a finding'
    end
  else
    catalina_base = input('catalina_base')
    tomcat_context_file = xml("#{catalina_base}/webapps/manager/META-INF/context.xml")
    valves = tomcat_context_file['//Valve/@className']

    describe.one do
      describe 'The RemoteAddrValve must be defined' do
        subject { valves }
        it { should include 'org.apache.catalina.valves.RemoteAddrValve' }
      end
      describe 'The RemoteCIDRValve must be defined' do
        subject { valves }
        it { should include 'org.apache.catalina.valves.RemoteCIDRValve' }
      end
    end
  end
end
