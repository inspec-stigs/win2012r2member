# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36677 - Optional component installation and component repair must be prevented from using Windows Update.'
control 'V-36677' do
  impact 0.1
  title 'Optional component installation and component repair must be prevented from using Windows Update.'
  desc 'Uncontrolled system updates can introduce issues to a system.  Obtaining update components from an outside source may also potentially provide sensitive information outside of the enterprise.  Optional component installation or repair must be obtained from an internal source.'
  tag 'stig', 'V-36677'
  tag severity: 'low'
  tag checkid: 'C-46856r2_chk'
  tag fixid: 'F-44727r1_fix'
  tag version: 'WN12-CC-000018'
  tag ruleid: 'SV-51606r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> "Specify settings for optional component installation and component repair" to "Enabled" and with "Never attempt to download payload from Windows Update" selected.'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\

Value Name: UseWindowsUpdate

Type: REG_DWORD
Value: 2'

# START_DESCRIBE V-36677
  
    describe registry_key({
      name: 'UseWindowsUpdate',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\Servicing',
    }) do
      its("UseWindowsUpdate") { should eq 2 }
    end

# STOP_DESCRIBE V-36677

end

