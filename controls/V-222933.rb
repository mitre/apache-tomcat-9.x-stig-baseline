control 'V-222933' do
  title 'Cookies must have http-only flag set.'
  desc '
  It is possible to steal or manipulate web application session and cookies
    without having a secure cookie. Configuring the secure flag injects the
    setting into the response header.

  The $CATALINA_BASE/conf/web.xml file controls how all applications handle
    cookies via the <cookie-config> element.
  '
  desc 'rationale', ''

  desc 'check', '
  From the Tomcat server console, run the following command:

  sudo grep -i -B10 -A1 \\/cookie-config $CATALINA_BASE/conf/web.xml

  If the command returns no results or if the <http-only> element is not set
    to true, this is a finding.

  EXAMPLE:
  <session-config>
     <session-timeout>15</session-timeout>
       <cookie-config>
         <http-only>true</http-only>
          <secure>true</secure>
       </cookie-config>
  </session-config>
  '
  desc 'fix', '
  From the Tomcat server console as a privileged user:

  edit the $CATALINA_BASE/conf/web.xml

  If the cookie-config section does not exist it must be added. Add or modify
    the <http-only> setting and set to true.

  EXAMPLE:
  <session-config>
     <session-timeout>15</session-timeout>
       <cookie-config>
         <http-only>true</http-only>
          <secure>true</secure>
       </cookie-config>
  </session-config>
  '

  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-AS-0000241'
  tag gid: 'V-222933'
  tag rid: 'SV-222933r615938_rule'
  tag stig_id: 'TCAT-AS-000080'
  tag fix_id: 'F-24594r426244_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  catalina_base = input('catalina_base')
  tomcat_web_file = xml("#{catalina_base}/conf/web.xml")

  describe 'The cookie-config element must be defined in web.xml' do
    subject { tomcat_web_file['//cookie-config'].empty? }
    it { should cmp false }
  end

  describe 'The secure parameter inside cookie-config element must be set to true' do
    subject { tomcat_web_file['//cookie-config/http-only'] }
    it { should cmp 'true' }
  end
end
