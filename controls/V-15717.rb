# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15717 - The system must be configured to allow a local or DOD-wide collector to request additional error reporting diagnostic data to be sent.'
control 'V-15717' do
  impact 0.5
  title 'The system must be configured to allow a local or DOD-wide collector to request additional error reporting diagnostic data to be sent.'
  desc 'Sending additional error reporting data provides valuable system diagnostic and vulnerability information that would otherwise not be generated nor collected.  This setting controls whether additional data in support of error reports can be sent to a local or DOD-wide reporting site.'
  tag 'stig', 'V-15717'
  tag severity: 'medium'
  tag checkid: 'C-58153r1_chk'
  tag fixid: 'F-62513r1_fix'
  tag version: 'WN12-ER-000004'
  tag ruleid: 'SV-53136r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> "Do not send additional data" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\

Value Name:  DontSendAdditionalData

Type:  REG_DWORD
Value:  0'

# START_DESCRIBE V-15717
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-15717

end

