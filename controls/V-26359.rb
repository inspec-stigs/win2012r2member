# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26359 - The Windows dialog box title for the legal banner must be configured.'
control 'V-26359' do
  impact 0.1
  title 'The Windows dialog box title for the legal banner must be configured.'
  desc 'Failure to display the logon banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources.'
  tag 'stig', 'V-26359'
  tag severity: 'low'
  tag checkid: 'C-47427r1_chk'
  tag fixid: 'F-46047r1_fix'
  tag version: 'WN12-SO-000023'
  tag ruleid: 'SV-53121r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive Logon: Message title for users attempting to log on" to "DoD Notice and Consent Banner", "US Department of Defense Warning Statement", or a site-defined equivalent. 

If a site-defined title is used, it can in no case contravene or modify the language of the banner text required in V-1089.'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: LegalNoticeCaption

Value Type: REG_SZ
Value: See message title options below

"DoD Notice and Consent Banner", "US Department of Defense Warning Statement", or a site-defined equivalent. 

If a site-defined title is used, it can in no case contravene or modify the language of the banner text required in V-1089.

Automated tools may only search for the titles defined above. If a site-defined title is used, a manual review will be required.'

# START_DESCRIBE V-26359
  
    describe registry_key({
      name: 'LegalNoticeCaption',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\System',
    }) do
      its("LegalNoticeCaption") { should eq See }
    end

# STOP_DESCRIBE V-26359

end

