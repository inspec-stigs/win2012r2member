# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1119 - The system must not boot into multiple operating systems (dual-boot).'
control 'V-1119' do
  impact 0.5
  title 'The system must not boot into multiple operating systems (dual-boot).'
  desc 'Allowing a system to boot into multiple operating systems (dual-booting) may allow security to be circumvented on a secure system.'
  tag 'stig', 'V-1119'
  tag severity: 'medium'
  tag checkid: 'C-47175r2_chk'
  tag fixid: 'F-45784r1_fix'
  tag version: 'WN12-GE-000010'
  tag ruleid: 'SV-52858r1_rule'
  tag fixtext: 'Ensure Windows Server 2012 is the only operating system installed for the system to boot into.  Remove alternate operating systems.'
  tag checktext: 'Verify the local system boots directly into Windows.  

Open Control Panel.
Select "System".
Select the "Advanced System Settings" link.
Select the "Advanced" tab.
Click the "Startup and Recovery" Settings button.  

If the drop-down list box "Default operating system:" shows any operating system other than Windows Server 2012, this is a finding.'

# START_DESCRIBE V-1119
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-1119

end

