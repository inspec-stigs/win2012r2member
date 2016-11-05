# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26605 - The Simple TCP/IP Services service must be disabled if installed.'
control 'V-26605' do
  impact 0.5
  title 'The Simple TCP/IP Services service must be disabled if installed.'
  desc 'Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption.'
  tag 'stig', 'V-26605'
  tag severity: 'medium'
  tag checkid: 'C-46977r1_chk'
  tag fixid: 'F-45254r1_fix'
  tag version: 'WN12-SV-000104'
  tag ruleid: 'SV-52239r2_rule'
  tag fixtext: 'Remove or disable the Simple TCP/IP Services (simptcp) service.'
  tag checktext: 'Verify the Simple TCP/IP (simptcp) service is not installed or is disabled. 

Run "Services.msc".

If the following is installed and not disabled, this is a finding:

Simple TCP/IP Services (simptcp)'

# START_DESCRIBE V-26605
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26605

end

