control 'V-222928' do
  title 'HTTP Strict Transport Security (HSTS) must be enabled.'
  desc '
  HTTP Strict Transport Security (HSTS) instructs web browsers to only use
    secure connections for all future requests when communicating with a
    website. Doing so helps prevent SSL protocol attacks, SSL stripping, cookie
    hijacking, and other attempts to circumvent SSL protection.

  Implementing HSTS requires testing of your web applications to ensure SSL
    certificates align correctly with application requirements and sub-domains
    if sub-domains are used. Ensure certificates are installed and working
    correctly. If sub-domains are in use, all sub-domains must be covered in
    the SSL/TLS certificate and the includeSubDomains directive must be
    specified in order for HSTS to function properly.
  '
  desc 'rationale', ''

  desc 'check', '
  From the Tomcat server console, run the following command:

  sudo grep -i -A5 -B8 hstsEnable $CATALINA_BASE/conf/web.xml file.

  If the httpHeaderSecurity filter is commented out or if hstsEnable is not
    set to "true", this is a finding.
  '
  desc 'fix', '
  From the Tomcat server as a privileged user, edit the web.xml file:

  sudo nano $CATALINA_BASE/conf/web.xml file.

  Uncomment the existing httpHeaderSecurity filter section or create the
    filter section using the following code:

  NOTE: includeSubDomains param-value and url-pattern values may change and
    can vary according to local deployment requirements.
  <filter>
  <filter-name>httpHeaderSecurity</filter-name>
  <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-
    class>
  <init-param>
   <param-name>hstsEnabled</param-name>
   <param-value>true</param-value>
  </init-param>
  <init-param>
   <param-name>maxAgeSeconds</param-name>
   <param-value>31536000</param-value>
   </init-param>
   <init-param>
   <param-name>includeSubDomains</param-name>
   <param-value>true</param-value>
   </init-param>
  <async-supported>true</async-supported>
  </filter>

  Create or uncomment the httpHeaderSecurity filter mapping:
  <filter-mapping>
    <filter-name>httpHeaderSecurity</filter-name>
    <url-pattern>/*</url-pattern>
    <dispatcher>REQUEST</dispatcher>
  </filter-mapping>
  '

  impact 0.5
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000015-AS-0000101'
  tag gid: 'V-222928'
  tag rid: 'SV-222928r754865_rule'
  tag stig_id: 'TCAT-AS-000030'
  tag fix_id: 'F-37850r754863_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']

  catalina_base = input('catalina_base')
  tomcat_web_file = xml("#{catalina_base}/conf/web.xml")

  describe tomcat_web_file do
    its('//filter') { should_not be_empty }
  end

  filter_count = tomcat_web_file['//filter'].count
  describe.one do
    (1..filter_count).each do |i|
      filter_child_count = tomcat_web_file["//filter[#{i}]//init-param"].count
      (1..filter_child_count).each do |j|
        describe tomcat_web_file do
          its(["//filter[#{i}]/filter-name"]) { should cmp 'httpHeaderSecurity' }
          its(["//filter[#{i}]/init-param[#{j}]/param-name"]) { should cmp 'hstsEnabled' }
          its(["//filter[#{i}]/init-param[#{j}]/param-value"]) { should cmp 'true' }
        end
      end
    end
  end
end
