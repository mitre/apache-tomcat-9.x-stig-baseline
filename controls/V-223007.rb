control 'V-223007' do
  title 'Hosted applications must be documented in the system security plan.'
  desc '
  The ISSM/ISSO must be cognizant of all applications operating on the Tomcat
    server, and must address any security implications associated with the
    operation of the applications.

  If unknown/undocumented applications are operating on the Tomcat server,
    these applications increase risk for the system due to not being managed,
    patched or monitored for unapproved activity on the system.
  '
  desc 'rationale', ''

  desc 'check', '
  Review the Tomcat servers System Security Plan/server documentation.

  Access the Tomcat server and review the $CATALINA_BASE/webapps folder.

  Ensure that all webapps are documented in the SSP.

  If the applications that are hosted on the Tomcat server are not documented
    in the SSP, this is a finding.
  '
  desc 'fix', '
  Document the applications that have an ATO on the Tomcat server.

  Retain the information in the SSP and present to the auditor in the event
    of a CCRI.
  '

  impact 0.5
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-223007'
  tag rid: 'SV-223007r615938_rule'
  tag stig_id: 'TCAT-AS-001710'
  tag fix_id: 'F-24668r426466_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  catalina_base = input('catalina_base')
  authorized_web_apps = input('authorized_web_apps')
  server_webapps = command("ls #{catalina_base}/webapps").stdout.split("\n")

  describe 'The list of applications hosted on the server must be the same list documented in the SSP' do
    subject { server_webapps - authorized_web_apps }
    it { should be_empty }
  end
end
