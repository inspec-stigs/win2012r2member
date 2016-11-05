# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1070 - Server systems must be located in a controlled access area, accessible only to authorized personnel.'
control 'V-1070' do
  impact 0.5
  title 'Server systems must be located in a controlled access area, accessible only to authorized personnel.'
  desc 'Inadequate physical protection can undermine all other security precautions utilized to protect the system.  This can jeopardize the confidentiality, availability, and integrity of the system.  Physical security is the first line of protection of any system.'
  tag 'stig', 'V-1070'
  tag severity: 'medium'
  tag checkid: 'C-47155r1_chk'
  tag fixid: 'F-45764r1_fix'
  tag version: 'WN12-00-000001'
  tag ruleid: 'SV-52838r1_rule'
  tag fixtext: 'Ensure servers are located in secure, access-controlled areas.'
  tag checktext: 'Verify servers are located in controlled access areas that are accessible only to authorized personnel.  If systems are not adequately protected, this is a finding.'

# START_DESCRIBE V-1070
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-1070

end

