# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3339 - Unauthorized remotely accessible registry paths must not be configured.'
control 'V-3339' do
  impact 1.0
  title 'Unauthorized remotely accessible registry paths must not be configured.'
  desc 'The registry is integral to the function, security, and stability of the Windows system.  Some processes may require remote access to the registry.  This setting controls which registry paths are accessible from a remote computer.  These registry paths must be limited, as they could give unauthorized individuals access to the registry.'
  tag 'stig', 'V-3339'
  tag severity: 'high'
  tag checkid: 'C-47200r3_chk'
  tag fixid: 'F-45809r2_fix'
  tag version: 'WN12-SO-000056'
  tag ruleid: 'SV-52883r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Remotely accessible registry paths" with the following entries:

System\CurrentControlSet\Control\ProductOptions 
System\CurrentControlSet\Control\Server Applications 
Software\Microsoft\Windows NT\CurrentVersion'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\

Value Name: Machine

Value Type: REG_MULTI_SZ
Value: see below

System\CurrentControlSet\Control\ProductOptions 
System\CurrentControlSet\Control\Server Applications 
Software\Microsoft\Windows NT\CurrentVersion

Legitimate applications may add entries to this registry value.  If an application requires these entries to function properly and is documented with the ISSO, this would not be a finding. Documentation must contain supporting information from the vendors instructions.'

# START_DESCRIBE V-3339
  
    describe registry_key({
      name: 'Machine',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths',
    }) do
      its("Machine") { should eq see }
    end

# STOP_DESCRIBE V-3339

end

