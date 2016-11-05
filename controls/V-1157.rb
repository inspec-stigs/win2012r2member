# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1157 - The Smart Card removal option must be configured to Force Logoff or Lock Workstation.'
control 'V-1157' do
  impact 0.5
  title 'The Smart Card removal option must be configured to Force Logoff or Lock Workstation.'
  desc 'Unattended systems are susceptible to unauthorized use and must be locked.  Configuring a system to lock when a smart card is removed will ensure the system is inaccessible when unattended.'
  tag 'stig', 'V-1157'
  tag severity: 'medium'
  tag checkid: 'C-47184r3_chk'
  tag fixid: 'F-45793r1_fix'
  tag version: 'WN12-SO-000027'
  tag ruleid: 'SV-52867r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive logon: Smart card removal behavior" to  "Lock Workstation" or "Force Logoff".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows NT\CurrentVersion\Winlogon\
 
Value Name: SCRemoveOption

Value Type: REG_SZ
Value: 1 (Lock Workstation) or 2 (Force Logoff)

If configuring this on servers causes issues such as terminating users remote sessions and the site has a policy in place that any other sessions on the servers such as administrative console logons, are manually locked or logged off when unattended or not in use, this would be acceptable. This must be documented with the ISSO.'

# START_DESCRIBE V-1157
  
    describe registry_key({
      name: 'SCRemoveOption',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
    }) do
      its("SCRemoveOption") { should eq 1 }
    end

# STOP_DESCRIBE V-1157

end

