control 'V-102525' do
  title "Tomcat servers must mutually authenticate proxy or load balancer
connections."
  desc  "Tomcat servers are often placed behind a proxy when exposed to both
trusted and untrusted networks. This is done for security and performance
reasons.  Tomcat does provide an HTTP server that can be configured to make
hosted applications available to clients directly. However, this HTTP server
has performance limitations and is not intended to be used on an enterprise
scale. Exposing this service to untrusted networks also violates the layered
security model and creates elevated risk of attack. To address these issues, a
proxy or load balancer can be placed in front of the Tomcat server. To ensure
the proxied connection is not spoofed, SSL mutual authentication must be
employed between Tomcat and the proxy.

    Not all Tomcat systems will have an RMF system categorization that warrants
mutual authentication protections. The site must determine if mutual
authentication is warranted based on their system RMF categorization and data
protection requirements. If the site determines that MA is not a requirement,
they can document a risk acceptance for not mutually authenticating proxy or
load balancer connections due to operational issues, or when the RMF system
categorization does not warrant the added level of protection.
  "
  desc  'rationale', ''
  desc  'check', "
    Review system security plan and/or system architecture documentation and
interview the system admin. Identify any proxy servers or load balancers that
provide services for the Tomcat server. If there are no load balancers or
proxies in use, this is not a finding.

    If there is a documented risk acceptance for not mutually authenticating
proxy or load balancer connections due to operational issues, or RMF system
categorization this is not a finding.

    Using the aforementioned documentation, identify each Tomcat IP address
that is served by a load balancer or proxy.

    From the Tomcat server as a privileged user, review the
$CATALINA_BASE/conf/server.xml file.  Review each $Connector element for the
address setting and the clientAuth setting.

    sudo grep -i -B1 -A5 connector $CATALINA_BASE/conf/server.xml

    If a connector has a configured IP address that is proxied or load balanced
and the clientAuth setting is not \"true\", this is a finding.
  "
  desc 'fix', "
    From the Tomcat server as a privileged user, edit the
$CATALINA_BASE/conf/server.xml file.

    Modify each $Connector element where the IP address is behind a proxy or
load balancer.

    Set clientAuth=\"true\" then identify the applications that are associated
with the connector and edit the associated web.xml files.  Assure the
<auth-method> is set to CLIENT-CERT.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000219-AS-000147'
  tag gid: 'V-102525'
  tag rid: 'SV-111465r1_rule'
  tag stig_id: 'TCAT-AS-000800'
  tag fix_id: 'F-108057r1_fix'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']

  load_balancer = input('behind_a_loadbalancer')
  ma = input('mutual_authentication_not_required')

  if !load_balancer || ma
    impact 0.0
    desc 'caveat', 'The service is not behind a proxy or load balacner or documented risk acceptance of not mutually authenticating
    proxy or load balancer connections. This is not a finding.'

    describe 'Server is not behind a load balancer or risk has been accepted' do
      skip 'The server is not behind a load balancer or proxy or the SSP indicates that the risk has been accepted of not mutually authenticating connections'
    end
  else
    catalina_base = input('catalina_base')
    tomcat_server_file = xml("#{catalina_base}/conf/server.xml")
    connector_count = tomcat_server_file['//Connector/'].count

    (1..connector_count).each do |i|
      conn = tomcat_server_file["//Connector[#{i}]/@address"]
      if !conn.empty?
        if conn[0] != '127.0.0.1' || conn[0] != '::1'
          describe 'The clientAuth element must be set to true' do
            subject { tomcat_server_file["//Connector[#{i}]/@clientAuth"] }
            it { should cmp 'true' }
          end
        end
      else
        describe 'Unable to find address field on Connector element' do
          subject { conn }
          it { should_not be_empty }
        end
      end
    end
  end
end
