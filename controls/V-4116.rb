# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-4116 - The system must be configured to ignore NetBIOS name release requests except from WINS servers.'
control 'V-4116' do
  impact 0.1
  title 'The system must be configured to ignore NetBIOS name release requests except from WINS servers.'
  desc 'Configuring the system to ignore name release requests, except from WINS servers, prevents a denial of service (DoS) attack.  The DoS consists of sending a NetBIOS name release request to the server for each entry in the servers cache, causing a response delay in the normal operation of the servers WINS resolution capability.'
  tag 'stig', 'V-4116'
  tag severity: 'low'
  tag checkid: 'C-47233r3_chk'
  tag fixid: 'F-45854r3_fix'
  tag version: 'WN12-SO-000043'
  tag ruleid: 'SV-52928r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers" to "Enabled".   

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the systems policy tools.)'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SYSTEM\CurrentControlSet\Services\Netbt\Parameters\

Value Name:  NoNameReleaseOnDemand

Value Type:  REG_DWORD
Value:  1'

# START_DESCRIBE V-4116
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-4116

end

