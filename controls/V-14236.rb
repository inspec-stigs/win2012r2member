# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-14236 - User Account Control must automatically deny standard user requests for elevation.'
control 'V-14236' do
  impact 0.5
  title 'User Account Control must automatically deny standard user requests for elevation.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting controls the behavior of elevation when requested by a standard user account.'
  tag 'stig', 'V-14236'
  tag severity: 'medium'
  tag checkid: 'C-47254r2_chk'
  tag fixid: 'F-45874r2_fix'
  tag version: 'WN12-SO-000079'
  tag ruleid: 'SV-52948r1_rule'
  tag fixtext: 'UAC requirements are NA on Server Core installations.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Behavior of the elevation prompt for standard users" to "Automatically deny elevation requests".'
  tag checktext: 'UAC requirements are NA on Server Core installations.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: ConsentPromptBehaviorUser

Value Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-14236
  
    describe registry_key({
      name: 'ConsentPromptBehaviorUser',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\System',
    }) do
      its("ConsentPromptBehaviorUser") { should eq 0 }
    end

# STOP_DESCRIBE V-14236

end

