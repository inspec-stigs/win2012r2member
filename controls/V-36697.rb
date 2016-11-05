# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36697 - Trusted app installation must be enabled to allow for signed enterprise line of business apps.'
control 'V-36697' do
  impact 0.1
  title 'Trusted app installation must be enabled to allow for signed enterprise line of business apps.'
  desc 'Enabling trusted app installation allows for enterprise line of business Windows 8 type apps.   A trusted app package is one that is signed with a certificate chain that can be successfully validated in the enterprise.  Configuring this ensures enterprise line of business apps are accessible.'
  tag 'stig', 'V-36697'
  tag severity: 'low'
  tag checkid: 'C-46867r1_chk'
  tag fixid: 'F-44813r1_fix'
  tag version: 'WN12-CC-000070'
  tag ruleid: 'SV-51738r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> App Package Deployment  -> "Allow all trusted apps to install" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Appx\

Value Name: AllowAllTrustedApps

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-36697
  
    describe registry_key({
      name: 'AllowAllTrustedApps',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\Appx',
    }) do
      its("AllowAllTrustedApps") { should eq 1 }
    end

# STOP_DESCRIBE V-36697

end

