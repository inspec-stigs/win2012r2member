# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-11806 - The system must be configured to prevent the display of the last username on the logon screen.'
control 'V-11806' do
  impact 0.1
  title 'The system must be configured to prevent the display of the last username on the logon screen.'
  desc 'Displaying the username of the last logged on user provides half of the userid/password equation that an unauthorized person would need to gain access.  The username of the last user to log on to a system must not be displayed.'
  tag 'stig', 'V-11806'
  tag severity: 'low'
  tag checkid: 'C-47247r2_chk'
  tag fixid: 'F-45867r1_fix'
  tag version: 'WN12-SO-000018'
  tag ruleid: 'SV-52941r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive logon: Do not display last user name" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: DontDisplayLastUserName

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-11806
  
    describe registry_key({
      name: 'DontDisplayLastUserName',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\System',
    }) do
      its("DontDisplayLastUserName") { should eq 1 }
    end

# STOP_DESCRIBE V-11806

end

