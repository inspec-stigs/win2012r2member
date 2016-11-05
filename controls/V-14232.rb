# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-14232 - IPSec Exemptions must be limited.'
control 'V-14232' do
  impact 0.1
  title 'IPSec Exemptions must be limited.'
  desc 'IPSec exemption filters allow specific traffic that may be needed by the system  for such things as Kerberos  authentication.  This setting configures Windows for specific IPSec exemptions.'
  tag 'stig', 'V-14232'
  tag severity: 'low'
  tag checkid: 'C-47251r2_chk'
  tag fixid: 'F-45871r2_fix'
  tag version: 'WN12-SO-000042'
  tag ruleid: 'SV-52945r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (NoDefaultExempt) Configure IPSec exemptions for various types of network traffic" to "Only ISAKMP is exempt (recommended for Windows Server 2003)".

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the systems policy tools.)'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\IPSEC\

Value Name: NoDefaultExempt

Value Type: REG_DWORD
Value: 3'

# START_DESCRIBE V-14232
  
    describe registry_key({
      name: 'NoDefaultExempt',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Services\IPSEC',
    }) do
      its("NoDefaultExempt") { should eq 3 }
    end

# STOP_DESCRIBE V-14232

end

