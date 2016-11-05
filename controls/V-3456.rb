# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3456 - Remote Desktop Services must delete temporary folders when a session is terminated.'
control 'V-3456' do
  impact 0.5
  title 'Remote Desktop Services must delete temporary folders when a session is terminated.'
  desc 'Remote desktop session temporary folders must always be deleted after a session is over to prevent hard disk clutter and potential leakage of information.  This setting controls the deletion of the temporary folders when the session is terminated.'
  tag 'stig', 'V-3456'
  tag severity: 'medium'
  tag checkid: 'C-47218r3_chk'
  tag fixid: 'F-45827r1_fix'
  tag version: 'WN12-CC-000103'
  tag ruleid: 'SV-52901r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Temporary Folders -> "Do not delete temp folder upon exit" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: DeleteTempDirsOnExit

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-3456
  
    describe registry_key({
      name: 'DeleteTempDirsOnExit',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows NT\Terminal Services',
    }) do
      its("DeleteTempDirsOnExit") { should eq 1 }
    end

# STOP_DESCRIBE V-3456

end

