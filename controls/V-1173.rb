# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1173 - The default permissions of global system objects must be increased.'
control 'V-1173' do
  impact 0.1
  title 'The default permissions of global system objects must be increased.'
  desc 'Windows systems maintain a global list of shared system resources such as DOS device names, mutexes, and semaphores.  Each type of object is created with a default DACL that specifies who can access the objects with what permissions.  If this policy is enabled, the default DACL is stronger, allowing nonadministrative users to read shared objects, but not modify shared objects that they did not create.'
  tag 'stig', 'V-1173'
  tag severity: 'low'
  tag checkid: 'C-47194r2_chk'
  tag fixid: 'F-45803r1_fix'
  tag version: 'WN12-SO-000076'
  tag ruleid: 'SV-52877r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Session Manager\

Value Name: ProtectionMode

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-1173
  
    describe registry_key({
      name: 'ProtectionMode',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Control\Session Manager',
    }) do
      its("ProtectionMode") { should eq 1 }
    end

# STOP_DESCRIBE V-1173

end

