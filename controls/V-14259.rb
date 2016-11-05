# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-14259 - Printing over HTTP must be prevented.'
control 'V-14259' do
  impact 0.5
  title 'Printing over HTTP must be prevented.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.   This setting prevents the client computer from printing over HTTP, which allows the computer to print to printers on the intranet as well as the Internet.'
  tag 'stig', 'V-14259'
  tag severity: 'medium'
  tag checkid: 'C-47304r2_chk'
  tag fixid: 'F-45924r1_fix'
  tag version: 'WN12-CC-000039'
  tag ruleid: 'SV-52997r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off printing over HTTP" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Printers\

Value Name: DisableHTTPPrinting

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-14259
  
    describe registry_key({
      name: 'DisableHTTPPrinting',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows NT\Printers',
    }) do
      its("DisableHTTPPrinting") { should eq 1 }
    end

# STOP_DESCRIBE V-14259

end

