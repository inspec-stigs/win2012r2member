# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-43240 - The network selection user interface (UI) must not be displayed on the logon screen (Windows 2012 R2).'
control 'V-43240' do
  impact 0.5
  title 'The network selection user interface (UI) must not be displayed on the logon screen (Windows 2012 R2).'
  desc 'Enabling interaction with the network selection UI allows users to change connections to available networks without signing into Windows.'
  tag 'stig', 'V-43240'
  tag severity: 'medium'
  tag checkid: 'C-49389r1_chk'
  tag fixid: 'F-49192r2_fix'
  tag version: 'WN12-CC-000140'
  tag ruleid: 'SV-56346r2_rule'
  tag fixtext: 'This requirement is NA for the initial release of Windows 2012.  It is applicable to Windows 2012 R2.

Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon -> "Do not display network selection UI" to "Enabled".'
  tag checktext: 'This requirement is NA for the initial release of Windows 2012.  It is applicable to Windows 2012 R2.

Verify the registry value below.  If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\

Value Name: DontDisplayNetworkSelectionUI

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-43240
  
    describe registry_key({
      name: 'DontDisplayNetworkSelectionUI',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'SOFTWARE\Policies\Microsoft\Windows\System',
    }) do
      its("DontDisplayNetworkSelectionUI") { should eq 1 }
    end

# STOP_DESCRIBE V-43240

end

