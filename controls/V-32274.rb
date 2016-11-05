# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-32274 - The DoD Interoperability Root CA 1 to DoD Root CA 2 cross-certificate must be installed into the Untrusted Certificates Store.'
control 'V-32274' do
  impact 0.5
  title 'The DoD Interoperability Root CA 1 to DoD Root CA 2 cross-certificate must be installed into the Untrusted Certificates Store.'
  desc 'To ensure users do not experience denial of service on NIPRNet when performing certificate-based authentication to DoD websites due to the system chaining to a root other than DoD Root CA 2, the DoD Interoperability Root CA 1 to DoD Root CA 2 cross-certificate must be installed in the Untrusted Certificate Store.  This only applies to NIPRNet systems.'
  tag 'stig', 'V-32274'
  tag severity: 'medium'
  tag checkid: 'C-49171r1_chk'
  tag fixid: 'F-48597r1_fix'
  tag version: 'WN12-PK-000003'
  tag ruleid: 'SV-52957r3_rule'
  tag fixtext: 'Install the DoD Interoperability Root CA 1 to DoD Root CA 2 cross-certificate on NIPRNet systems only.  Administrators should run the Federal Bridge Certification Authority (FBCA) Cross-Certificate Removal Tool once as an administrator and once as the current user.  The FBCA Cross-Certificate Remover tool and user guide is available on IASE at http://iase.disa.mil/pki-pke/function_pages/tools.html.'
  tag checktext: 'Verify the DoD Root CA 2 certificate issued by DoD Interoperability Root CA 1 is installed on NIPRNet systems as an Untrusted Certificate using the Certificates MMC snap-in:
Run "MMC".
Select "File", "Add/Remove Snap-in".
Select "Certificates", click "Add".
Select "Computer account", click "Next".
Select "Local computer: (the computer this console is running on)", click "Finish".
Click "OK".
Expand "Certificates" and navigate to "Untrusted Certificates\Certificates".
Search in the center pane for "DoD Root CA 2" under "Issued To" with "DoD Interoperability Root CA 1" as "Issued By".

If there is no entry for this certificate, this is a finding.

Select the certificate.
Right click and select "Open".
Select the "Details" Tab.
Scroll to the bottom and select "Thumbprint Algorithm".
Verify the Value is "sha1".

If the value for "Thumbprint Algorithm" is not "sha1", this is a finding.

Next select "Thumbprint".

If the value for the "Thumbprint" field is not
"99:c4:94:ec:e4:fc:09:3e:ee:13:c4:d6:5b:1b:1e:01:b9:b5:d4:34", this is a finding.'

# START_DESCRIBE V-32274
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-32274

end

