control 'V-102491' do
  title 'DefaultServlet directory listings parameter must be disabled.'
  desc  "The DefaultServlet serves static resources as well as directory
listings. It is declared globally in $CATALINA_BASE/conf/web.xml and by default
is configured with the directory \"listings\" parameter set to disabled. If no
welcome file is present and the \"listings\" setting is enabled, a directory
listing is shown. Directory listings must be disabled."
  desc  'rationale', ''
  desc  'check', "
    From the Tomcat server run the following OS command:

    sudo cat $CATALINA_BASE/conf/web.xml |grep -i -A10 -B2 defaultservlet

    The above command will include ten lines after and two lines before the
occurrence of \"defaultservlet\". Some systems may require that the user
increase the after number (A10) in order to determine the \"listings\"
param-value.

    If the \"listings\" param-value for the \"DefaultServlet\" servlet class
does not = \"false\", this is a finding.
  "
  desc 'fix', "
    From the Tomcat server as a privileged user:

    Edit the $CATALINA_BASE/conf/web.xml file.

    Examine the <init-param> elements within the <Servletclass> element, if the
\"listings\" <param-value>element is \"true\" change the \"listings\"
<param-value> to read \"false\".

    sudo systemctl restart tomcat
    sudo systemctl daemon-reload
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-102491'
  tag rid: 'SV-111433r1_rule'
  tag stig_id: 'TCAT-AS-000520'
  tag fix_id: 'F-108025r1_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  catalina_base = input('catalina_base')
  tomcat_web_file = xml("#{catalina_base}/conf/web.xml")
  servlets = tomcat_web_file['//servlet/servlet-class']

  servlet_index = servlets.index('org.apache.catalina.servlets.DefaultServlet') + 1
  params = tomcat_web_file["//servlet[#{servlet_index}]/init-param/param-name"]
  listings_index = params.index('listings') + 1
  listings = tomcat_web_file["//servlet[#{servlet_index}]/init-param[#{listings_index}]/param-value"]

  describe 'The default param for the DefaultServlet element must be set to true' do
    subject { listings }
    it { should cmp 'true' }
  end
end
