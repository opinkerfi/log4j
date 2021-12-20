# Log4j

## Upplýsingar

Þann 9. desember var opinberaður alvarlegur veikleiki ([CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228) & [CVE-2021-45046](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45046)) í hugbúnaðarpakka sem kallast Apache Log4j. Þessi hugbúnaður er notaður sem hjálpartól í mörgum þekktum og útbreiddum hugbúnaði. Um er að ræða Java hugbúnað sem finnst á fjölmörgum stöðum á internetinu og innan fyrirtækja.

Hlutverk Log4j sem hjálpartól er að halda utan um og skrá upplýsingar sem geta meðal annars verið upplýsingar sem notendur kerfa t.d. vefkerfa láta frá sér, en getur einnig verið upplýsingar sem geta komið í gegnum tölvupóst eða aðrar leiðir svo lengi sem Log4j er að taka við upplýsingunum.

Gott dæmi gæti verið vefur sem keyrir WordPress en notar Apache Solr til að vinna úr (e. index) og bjóða upp á leitarvél. Þegar notandi slær inn texta í leitarstreng og ef leitarstrengurinn er skráður í gegnum Log4j í log skrá til geymslu þá getur utanaðkomandi aðili slegið inn sérstaka strengi sem Log4j keyrir (e. executes).

Í þeim tilfellum getur utanaðkomandi aðili verið kominn með aðgang að tölvunni eða kerfinu sem um ræðir. Ef utanaðkomandi aðili nær aðgengi að tölvunni eða kerfinu þá getur hann lesið eða hlerað upplýsingar sem geta verið viðkvæmar og mögulega stjórnað tölvunni.

Í flestum tilfellum sem þetta hjálpartól er notað er verið að notast við hugbúnað frá þekktum hugbúnaðarframleiðendum og í þeim tilfellum þurfa þeir að gefa út uppfærslu. Það getur tekið tíma og því getur verið nauðsynlegt að grípa til tímabundinna aðgerða.

## Aðgerðir

### Forgangur 1

* Meta hvort að fyrirtækið þitt sé með kerfi opin fyrir allt internetið. Dæmi geta verið VPN þjónustur, vefkerfi eða myndavélakerfi.
* Er um að ræða Java hugbúnað? Erfitt getur verið að sjá hvort um er að ræða Java hugbúnað, best er að leita að upplýsingum frá framleiðenda.
* Ef ekki er hægt að uppfæra og ganga úr skugga að uppfærslan leysi vandamálið, meta þá hvort hægt sé að takmarka aðgengi strax t.d. loka alveg frá interneti eða opna fyrir takmarkað IP tölu mengi (IP range).
* Möguleiki er að færa vefþjónustuna á bakvið kerfi sem hreinsar mögulega árásir.
* Ekki gleyma innri java kerfum sem mögulega eru að taka við upplýsingum frá aðilum á internetinu og vinna úr (e. process).

### Forgangur 2

* Meta allan innri hugbúnað sem er að nota Java.
* Útbúa uppfærslu eða aðgerðaráætlun til að taka á vandamálinu.
* Fylgjast með tilkynningum frá hugbúnaðarframleiðendum.
* Fylgjast vel með fréttum og tilkynningum um vandamálið.

## Greinar

### Nánari upplýsingar

* [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228)
* [CVE-2021-45046](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45046)
* [Fjarskiptastofa – Netöryggssveitin CERT-IS hefur virkjað samhæfingarferli vegna alvarlegs veikleika í algengum hugbúnaði](https://www.fjarskiptastofa.is/fjarskiptastofa/tolfraedi-og-gagnasafn/frettasafn/frett/fr%C3%A9ttir/netoryggssveitin-cert-is-hefur-virkjad-samhaefingarstod-vegna-alvarlegs-veikleika-i-algengum-hugbunadi)

### Ráðleggingar eða yfirlýsingar frá birgjum

* [Amazon](https://aws.amazon.com/security/security-bulletins/AWS-2021-006/)
* [Microsoft](https://msrc-blog.microsoft.com/2021/12/11/microsofts-response-to-cve-2021-44228-apache-log4j2/)
* [Nutanix](https://download.nutanix.com/alerts/Security_Advisory_0023.pdf)
* [F5](https://support.f5.com/csp/article/K19026212)
* [Fortinet](https://www.fortiguard.com/psirt/FG-IR-21-245)
* [HPe](https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=hpesbgn04215en_us)
* [Dell](https://www.dell.com/support/kbdoc/en-is/000194372/dsn-2021-007-dell-response-to-apache-log4j-remote-code-execution-vulnerability)
* [Cisco](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd)
* [Red Hat](https://access.redhat.com/security/vulnerabilities/RHSB-2021-009)
* [VMWare](https://www.vmware.com/security/advisories/VMSA-2021-0028.html)
* [Unifi](https://community.ui.com/releases/UniFi-Network-Application-6-5-54/d717f241-48bb-4979-8b10-99db36ddabe1)
* [VEEAM](https://forums.veeam.com/veeam-backup-for-azure-f59/log4j-cve-2021-44228-vulnerability-t78225.html#p438231)
* [Atlassian](https://confluence.atlassian.com/security/multiple-products-security-advisory-log4j-vulnerable-to-remote-code-execution-cve-2021-44228-1103069934.html)
* [CloudFlare](https://blog.cloudflare.com/cve-2021-44228-log4j-rce-0-day-mitigation/)
* [Ahsay]("https://wiki.ahsay.com/doku.php?id=public:announcement:cve-2021-44228_log4j")
* [Solarwinds](https://www.solarwinds.com/trust-center/security-advisories/cve-2021-44228)

## Algengur hugbúnaður á íslandi

Hér er að finna lista yfir hugbúnað, búnað og kerfi sem er algengur.

?> Hlekkir undir **Hugbúnaður** eru tilvísanir í ráðleggingar eða skýringar frá framleiðanda.

| Hugbúnaður | Staða | Uppfært | Athugasemd | 
| ---------- | ----- | ------- | ---------- | 
| [Office 365](https://msrc-blog.microsoft.com/2021/12/11/microsofts-response-to-cve-2021-44228-apache-log4j2/)       | Í lagi      | 15.12.21 | Microsoft telur að veikleikinn eigi ekki við. |
| [Microsoft 365](https://msrc-blog.microsoft.com/2021/12/11/microsofts-response-to-cve-2021-44228-apache-log4j2/)    | Í lagi      | 15.12.21 | Microsoft telur að veikleikinn eigi ekki við. |
| [PowerBI](https://msrc-blog.microsoft.com/2021/12/11/microsofts-response-to-cve-2021-44228-apache-log4j2/)          | Í lagi      | 15.12.21 | Microsoft telur að veikleikinn eigi ekki við. |
| [Minecraft](https://help.minecraft.net/hc/en-us/articles/4416199399693-Security-Vulnerability-in-Minecraft-Java-Edition)        | Berskjaldað | 15.12.21 | Þarf að uppfæra í 1.18.1. Útgáfur undir 1.7 eru í lagi. |
| [Unifi Video](https://aikester.com/2021/addressing-the-log4j-vulnerability-in-unifi-video-3.10.13/) | Berskjaldað | 18.12.21 | Ekki er í boði patch frá framleiðanda, kerfi komið úr stuðningi |
| [Unifi Controller](https://community.ui.com/releases/UniFi-Network-Application-6-5-54/d717f241-48bb-4979-8b10-99db36ddabe1) | Berskjaldað | 15.12.21 | Komið út patch sem þarf að uppfæra í. |
| Cisco Webex Meetings Server | Bergskjaldað + fix | 15.12.21 | Komið út fix CWMS-3.0MR4SP2 og CWMS-4.0MR4SP2 (CSCwa47283)| | 
| [Cisco Identity Services Engine (ISE)](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd)| Berskjaldað + hotfix | 15.12.21 | Hotfix komið fyrir 2.4, 2.6, 2.7, 3.0 og 3.1 (CSCwa47133) | 
| Cisco AnyConnect Secure Mobility Client | Í lagi | 15.12.21 | Anyconnect client er í lagi | 
| Cisco Meraki | Í lagi | 15.12.21 | GO, MR, MS, MT, MV, MX, SM og Z-series |
| Cisco Adaptive Security Appliance (ASA) & ASAv Software | Í lagi | 15.12.21 | ASA eldveggir í lagi | 
| Cisco Adaptive Security Device Manager | Í lagi | 15.12.21 | ASDM management viðmót í lagi |
| Cisco Firepower Thread Defense (FTD) managed by Cisco Firepower Management Center | Í lagi | 15.12.21 | |
| Cisco Firepower Threat Defense (FTD) managed by Firepower Device Manager (FDM) | Berskjaldað | 15.12.21 | Cisco er að vinna að lausn (CSCwa46963) |
| Cisco Nexus switches | Í lagi | 15.12.21 | Á við um 3000, 5500, 5600, 6000, 7000, 9000 |
| Cisco Aironet Access Points | Í lagi | 15.12.21 | Cisco aironet þráðlausir punktar |
| Cisco Catalyst 9100 Series Access Points | Í lagi | 15.12.21 | Cisco catalyst 9100 þráðlausir punktar |
| Cisco Catalyst 9800 Series Wireless Controllers | Í lagi | 15.12.21 | Cisco Catalyst 9800 þráðlausir controllerar |
| Cisco IOS Access Points | Í lagi | 15.12.21 | Cisco IOS þráðlausir punktar |
| Cisco DNA Center | Berskjaldað + fix | 15.12.21 | Fix komið (CSCwa47322) | |
| Cisco Email Security Appliance (ESA) | Í lagi | 15.12.21 | |
| Cisco Web Security Appliance (WSA) | Í lagi | 15.12.21 | |
| Cisco Modeling Labs | Í lagi | 15.12.21 | |
| Cisco Duo Security | Í lagi | 15.12.21 | Innihélt veikleika, en leyst | |
| Cisco Umbrella DNS / SIG | Í lagi | 15.12.21 | Innihélt veikleika en leyst | |
| Cisco SecureX | Í lagi | 15.12.21 | | 
| Cisco IOS and IOS XE Software | Í lagi | 15.12.21 | |
| Cisco IOS XR Software | Í lagi | 15.12.21 | |
| Cisco Webex Meetings | Í lagi | 15.12.21 | Innihélt veikleika, en leyst | |
| HPE SimpliVity | Berskjaldað | 15.12.21 | HPE vinnur að lausn |
| HPE StoreServ Management Console (SSMC) All versions | Berskjaldað | 15.12.21 | HPE vinnur að lausn  |
| HPE Hyper Converged 380 All versions | Berskjaldað | 15.12.21|| HPE vinnur að lausn  |
| HPE 3PAR Service Processor All versions | Berskjaldað | 15.12.21 | HPE vinnur að lausn  |
| [Nagios](https://www.nagios.com/news/2021/12/update-on-apache-log4j-vulnerability/) | Í lagi | 15.12.21 | Nagios Core og Nagios XI |  |
| [Zabbix](https://blog.zabbix.com/zabbix-not-affected-by-the-log4j-exploit/17873/) | Í lagi | 18.12.21 | Vöktunarkerfið Zabbix |  |
| [1Password](https://1password.community/discussion/comment/622615) | Óvíst | 15.12.21 | Opinber tilkynning ekki komin, en gefið til kynna að það sé í lagi |  |
| [Citrix Hypervisor (XenServer)](https://support.citrix.com/article/CTX335705) | Í lagi | 15.12.21 | XenServer er í lagi | |
| [Citrix Virtual Apps and Desktops (XenApp & XenDesktop)](https://support.citrix.com/article/CTX335705) | Í skoðun | 15.12.21 | Er í greiningu hjá framleiðanda | |
| [Ahsay](https://wiki.ahsay.com/doku.php?id=public:announcement:cve-2021-44228_log4j) | | 15.12.21 | AhsayCBS, AhsayOBM, AhsayACB, AhsayUBS 8.5.4.86 (og nýrra) og 7.17.2.2 (með hotfix 7.17.2.127+) og útgáfur undir 6.29.x) í lagi | |
| [TimeXtender](https://support.timextender.com/hc/en-us/articles/4413724826897-Apache-Log4j) | Í lagi | 15.12.21 |  |  | 
| [MongoDB Atlas Search](https://www.mongodb.com/blog/post/log4shell-vulnerability-cve-2021-44228-and-mongodb) | Berskjaldað + fix | 15.12.21 |  |  |
| MongoDB aðrar vörur | Í lagi | 15.12.21 | | | 
| [MariaDB](https://mariadb.com/resources/blog/log4shell-and-mariadb-cve-2021-44228/) | Í lagi | 15.12.21 | |  |
| Amazon S3 | Berskjaldað + lagað | 15.21.21 |  | |
| [Solarwinds Server & Application Monitor](https://www.solarwinds.com/trust-center/security-advisories/cve-2021-44228) | Berskjaldað + fix | 15.12.21 |  |  |
| [Solarwinds Database Performance Analyzer](https://www.solarwinds.com/trust-center/security-advisories/cve-2021-44228) | Berskjaldað + fix |  15.12.21 | |  |
| Solarwinds Orion Platform | Í lagi | 15.12.21 |  | |
| [Enghouse QMS](https://github.com/opinkerfi/log4j/blob/560ff977d620513bf82f4eea15b4d863736bc9b1/docs/EXTERNAL_QMS_Enghouse_Log4j_vulnerability_statement_131221.pdf) | Berskjaldað | 16.12.21 | |  |
| [Tableau / Tableau Reader, Tableau Public Desktop Client](https://kb.tableau.com/articles/issue/Apache-Log4j2-vulnerability-Log4shell) | Berskjaldað | 16.12.21 | |  |
| ATlassian Bitbucket Server | Berskjaldað | 16.12.21 | | |
| Atlassian Confluence | Í lagi | 16.12.21 | | |
| Atlassian Jira | Í lagi | 16.12.21 | | |
| [Splunk viðbætur](https://www.splunk.com/en_us/blog/bulletins/splunk-security-advisory-for-apache-log4j-cve-2021-44228.html) | Berskjaldað | 16.12.21 | | | 
| [Jenksins](https://www.jenkins.io/blog/2021/12/10/log4j2-rce-CVE-2021-44228/) | Í lagi | 16.12.21 | Jenksins er í lagi, en skoða þarf viðbætur sérstaklega vel |  |
| Discord | Uppl vantar | 16.12.21 | | |
| [Apache Kafka](https://kafka.apache.org/cve-list) | Í lagi | 16.12.21 | | | 
| [Plex](https://www.reddit.com/r/PleX/comments/rdolem/the_internet_is_on_fire_with_this_log4j/) | Í lagi* | 18.12.21 | Formlega tilkynningu vantar frá framleiðanda |  |
| [Plesk](https://support.plesk.com/hc/en-us/articles/4412182812818-CVE-2021-44228-vulnerability-in-log4j-package-of-Apache) | Í lagi | 16.12.21 |
| [Red Hat Enterprise Linux](https://access.redhat.com/security/vulnerabilities/RHSB-2021-009) | Í lagi* | 19.12.21 | Red Hat Linux er í lagi, en mælt er með að keyra update |  |
| Red Hat Ansible | Í lagi | 19.12.21 | | https://access.redhat.com/security/vulnerabilities/RHSB-2021-009 | 
| [Red Hat ýmsar vörur](https://access.redhat.com/security/vulnerabilities/RHSB-2021-009) | Í lagi | 19.12.21 | m.a. Certificate Sysetm, Directory Server, CloudForms, Satellite, Ceph, Gluster, Openstack platform (fyrir utan 13), RHEV |  |
| [Red Hat ýmsar vörur](https://access.redhat.com/security/vulnerabilities/RHSB-2021-009) | Berskjaldað | 19.12.21 | m.a. Red Hat Enterprise Application Platform 7, Openshift 4, Openshift 3.11, Fuse, OpenShift Logging, Openstack Platform 13, Process Automation Manager |  |
| [Elasticserach](https://discuss.elastic.co/t/elasticsearch-5-0-0-5-6-10-and-6-0-0-6-3-2-log4j-cve-2021-44228-cve-2021-45046-remediation/292054) | Berskjaldað | 19.12.21 | |  |
| [Zammad](https://community.zammad.org/t/cve-2021-44228-cve-2021-45046-elasticsearch-users-be-aware/8256) | Berskjaldað | 19.12.21 | Verkbeiðnakerfið Zammad nýtir elasticsearch |  |


## Um þessa síðu

Þessi síða er styrkt af Opnum Kerfum og er viðhaldið af starfsfólki Opinna Kerfa. Ef þú ert með athugasemd eða upplýsingar sem þú vilt sjá á þessari síðu þá er það velkomið að senda inn breytingar og viðbætur.


### Get ég hjálpað?

Öllum er frjálst að leggja til breytingar á þessari síðu. Ef þú vilt leggja lið, þá mælum við með eftirfarandi verklagi:

1. Forka [log4j](https://github.com/opinkerfi/log4j) kóðahirsluna inn á github
2. Uppfæra efni á forsíðu eða stofna aðrar síður.
3. Framkvæma breytingar á forsíðu `docs/Readme.md` eða með því að stofna aðrar síður undir `docs/`
4. Búa til pull request sem verður yfirfarið.