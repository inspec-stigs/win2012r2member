# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1172 - Users must be warned in advance of their passwords expiring.'
control 'V-1172' do
  impact 0.1
  title 'Users must be warned in advance of their passwords expiring.'
  desc 'Creating strong passwords that can be remembered by users requires some thought.  By giving the user advance warning, the user has time to construct a sufficiently strong password.  This setting configures the system to display a warning to users telling them how many days are left before their password expires.'
  tag 'stig', 'V-1172'
  tag severity: 'low'
  tag checkid: 'C-47193r2_chk'
  tag fixid: 'F-45802r1_fix'
  tag version: 'WN12-SO-000025'
  tag ruleid: 'SV-52876r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive Logon: Prompt user to change password before expiration" to "14" days or more.'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows NT\CurrentVersion\Winlogon\

Value Name: PasswordExpiryWarning

Value Type: REG_DWORD
Value: 14 (or greater)'

# START_DESCRIBE V-1172
  
    describe registry_key({
      name: 'PasswordExpiryWarning',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
    }) do
      its("PasswordExpiryWarning") { should eq 14 }
    end

# STOP_DESCRIBE V-1172

end

