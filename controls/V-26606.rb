# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26606 - The Telnet service must be disabled if installed.'
control 'V-26606' do
  impact 0.5
  title 'The Telnet service must be disabled if installed.'
  desc 'Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption.'
  tag 'stig', 'V-26606'
  tag severity: 'medium'
  tag checkid: 'C-46978r1_chk'
  tag fixid: 'F-45255r1_fix'
  tag version: 'WN12-SV-000105'
  tag ruleid: 'SV-52240r2_rule'
  tag fixtext: 'Remove or disable the Telnet (tlntsvr) service.'
  tag checktext: 'Verify the Telnet (tlntsvr) service is not installed or is disabled. 

Run "Services.msc".

If the following is installed and not disabled, this is a finding:

Telnet (tlntsvr)'

# START_DESCRIBE V-26606
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26606

end

