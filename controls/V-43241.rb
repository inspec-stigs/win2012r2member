# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-43241 - The setting to allow Microsoft accounts to be optional for modern style apps must be enabled (Windows 2012 R2).'
control 'V-43241' do
  impact 0.1
  title 'The setting to allow Microsoft accounts to be optional for modern style apps must be enabled (Windows 2012 R2).'
  desc 'Control of credentials and the system must be maintained within the enterprise.  Enabling this setting allows enterprise credentials to be used with modern style apps that support this, instead of Microsoft accounts.'
  tag 'stig', 'V-43241'
  tag severity: 'low'
  tag checkid: 'C-49390r1_chk'
  tag fixid: 'F-49195r2_fix'
  tag version: 'WN12-CC-000141'
  tag ruleid: 'SV-56353r2_rule'
  tag fixtext: 'This requirement is NA for the initial release of Windows 2012.  It is applicable to Windows 2012 R2.

Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> App Runtime -> "Allow Microsoft accounts to be optional" to "Enabled".'
  tag checktext: 'This requirement is NA for the initial release of Windows 2012.  It is applicable to Windows 2012 R2.

Verify the registry value below.  If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

Value Name: MSAOptional

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-43241
  
    describe registry_key({
      name: 'MSAOptional',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',
    }) do
      its("MSAOptional") { should eq 1 }
    end

# STOP_DESCRIBE V-43241

end

