control 'V-222953' do
  title 'DefaultServlet debug parameter must be disabled.'
  desc '
  The DefaultServlet serves static resources as well as serves the directory
    listings (if directory listings are enabled). It is declared globally in
    $CATALINA_BASE/conf/web.xml and by default is configured with the "debug"
    parameter set to 0, which is disabled. Changing this to a value of 1 or
    higher sets the servlet to print debug level information. DefaultServlet
    debug setting must be set to 0 (disabled).
  '
  desc 'rationale', ''

  desc 'check', '
  From the Tomcat server run the following OS command:

  sudo cat $CATALINA_BASE/conf/web.xml |grep -i -A10 -B2 defaultservlet

  The above command will include ten lines after and two lines before the
    occurrence of "defaultservlet". Some systems may require that the user
    increase the after number (A10) in order to determine the "debug" param-
    value.

  If the "debug" param-value for the "DefaultServlet" servlet class does
    not = 0, this is a finding.
  '
  desc 'fix', '
  From the Tomcat server as a privileged user:

  Edit the $CATALINA_BASE/conf/web.xml file.

  Examine the <init-param> elements within the <Servletclass> element, if the
    "debug" <param-value>element is not "0"" change the "debug" <param-
    value> to read "0".

  sudo systemctl restart tomcat
  sudo systemctl daemon-reload
  '

  impact 0.5
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-222953'
  tag rid: 'SV-222953r615938_rule'
  tag stig_id: 'TCAT-AS-000510'
  tag fix_id: 'F-24614r426304_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  catalina_base = input('catalina_base')
  tomcat_web_file = xml("#{catalina_base}/conf/web.xml")
  servlets = tomcat_web_file['//servlet/servlet-class']

  servlet_index = servlets.index('org.apache.catalina.servlets.DefaultServlet') + 1
  params = tomcat_web_file["//servlet[#{servlet_index}]/init-param/param-name"]
  param_index = params.index('debug') + 1
  debug = tomcat_web_file["//servlet[#{servlet_index}]/init-param[#{param_index}]/param-value"]

  describe 'The default param for the DefaultServlet element must be set to 0' do
    subject { debug }
    it { should cmp 0 }
  end
end
