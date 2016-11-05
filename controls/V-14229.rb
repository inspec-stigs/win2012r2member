# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-14229 - Auditing of Backup and Restore Privileges must be turned off.'
control 'V-14229' do
  impact 0.5
  title 'Auditing of Backup and Restore Privileges must be turned off.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.   This setting prevents the system from generating audit events for every file backed up or restored, which could fill the security log in Windows, making it difficult to identify actual issues.'
  tag 'stig', 'V-14229'
  tag severity: 'medium'
  tag checkid: 'C-47249r3_chk'
  tag fixid: 'F-45869r1_fix'
  tag version: 'WN12-SO-000008'
  tag ruleid: 'SV-52943r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Audit: Audit the use of Backup and Restore privilege" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa\

Value Name: FullPrivilegeAuditing

Value Type: REG_BINARY
Value: 0'

# START_DESCRIBE V-14229
  
    describe registry_key({
      name: 'FullPrivilegeAuditing',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Control\Lsa',
    }) do
      its("FullPrivilegeAuditing") { should eq 0 }
    end

# STOP_DESCRIBE V-14229

end

