# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-14230 - Audit policy using subcategories must be enabled.'
control 'V-14230' do
  impact 0.5
  title 'Audit policy using subcategories must be enabled.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.   This setting allows administrators to enable more precise auditing capabilities.'
  tag 'stig', 'V-14230'
  tag severity: 'medium'
  tag checkid: 'C-47250r2_chk'
  tag fixid: 'F-45870r1_fix'
  tag version: 'WN12-SO-000009'
  tag ruleid: 'SV-52944r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa\

Value Name: SCENoApplyLegacyAuditPolicy

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-14230
  
    describe registry_key({
      name: 'SCENoApplyLegacyAuditPolicy',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Control\Lsa',
    }) do
      its("SCENoApplyLegacyAuditPolicy") { should eq 1 }
    end

# STOP_DESCRIBE V-14230

end

