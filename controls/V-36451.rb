# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36451 - Policy must require that administrative accounts not be used with applications that access the Internet, such as web browsers, or with potential Internet sources, such as email.'
control 'V-36451' do
  impact 1.0
  title 'Policy must require that administrative accounts not be used with applications that access the Internet, such as web browsers, or with potential Internet sources, such as email.'
  desc 'Using applications that access the Internet or have potential Internet sources using administrative privileges exposes a system to compromise.  If a flaw in an application is exploited while running as a privileged user, the entire system could be compromised.  Web browsers and email are common attack vectors for introducing malicious code and must not be run with an administrative account.  Since administrative accounts may generally change or work around technical restrictions for running a web browser or other applications, it is essential that policy requires administrative accounts to not access the Internet or use applications, such as email.  The policy should define specific exceptions for local service administration.  These exceptions may include HTTP(S)-based tools that are used for the administration of the local system, services, or attached devices.'
  tag 'stig', 'V-36451'
  tag severity: 'high'
  tag checkid: 'C-46841r2_chk'
  tag fixid: 'F-44707r2_fix'
  tag version: 'WN12-00-000008'
  tag ruleid: 'SV-51578r1_rule'
  tag fixtext: 'Establish a site policy to prohibit the use of applications that access the Internet, such as web browsers, or with potential Internet sources, such as email, by administrative accounts.  Ensure the policy is enforced.'
  tag checktext: 'Determine whether site policy prohibits the use of applications that access the Internet, such as web browsers, or with potential Internet sources, such as email, by administrative accounts, except as necessary for local service administration.  If it does not, this is a finding.'

# START_DESCRIBE V-36451
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-36451

end

