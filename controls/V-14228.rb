# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-14228 - Auditing the Access of Global System Objects must be turned off.'
control 'V-14228' do
  impact 0.5
  title 'Auditing the Access of Global System Objects must be turned off.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. This setting prevents the system from setting up a default system access control list for certain system objects, which could create a very large number of security events, filling the security log in Windows and making it difficult to identify actual issues.'
  tag 'stig', 'V-14228'
  tag severity: 'medium'
  tag checkid: 'C-47435r2_chk'
  tag fixid: 'F-46055r1_fix'
  tag version: 'WN12-SO-000007'
  tag ruleid: 'SV-53129r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Audit: Audit the access of global system objects" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa\

Value Name: AuditBaseObjects

Value Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-14228
  
    describe registry_key({
      name: 'AuditBaseObjects',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Control\Lsa',
    }) do
      its("AuditBaseObjects") { should eq 0 }
    end

# STOP_DESCRIBE V-14228

end

