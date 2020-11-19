# encoding: UTF-8

control 'V-102447' do
  title 'Cookies must have secure flag set.'
  desc  "It is possible to steal or manipulate web application session and
cookies without having a secure cookie. Configuring the secure flag injects the
setting into the response header.

    The $CATALINA_BASE/conf/web.xml file controls how all applications handle
cookies via the $cookie-config element.
  "
  desc  'rationale', ''
  desc  'check', "
    From the Tomcat server console, run the following command:

    sudo grep -i -B10 -A1 \\/cookie-config $CATALINA_BASE/conf/web.xml

    If the command returns no results or if the <secure> element is not set to
true, this is a finding.

    EXAMPLE:
    <session-config>
       <session-timeout>15</session-timeout>
         $cookie-config
           <http-only>true</http-only>
            <secure>true</secure>
         </cookie-config>
    </session-config>
  "
  desc  'fix', "
    From the Tomcat server console as a privileged user:

    edit the $CATALINA_BASE/conf/web.xml

    If the cookie-config section does not exist it must be added. Add or modify
the <secure> setting and set to true.

    EXAMPLE:
    <session-config>
       <session-timeout>15</session-timeout>
         $cookie-config
           <http-only>true</http-only>
            <secure>true</secure>
         </cookie-config>
    </session-config>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag gid: 'V-102447'
  tag rid: 'SV-111395r1_rule'
  tag stig_id: 'TCAT-AS-000070'
  tag fix_id: 'F-107987r1_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

