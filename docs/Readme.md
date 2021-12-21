# Log4j

## Upplýsingar

Þann 9. desember 2021 var opinberaður alvarlegur veikleiki ([CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228) & [CVE-2021-45046](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45046)) í hugbúnaðarpakka sem kallast Apache Log4j. Þessi hugbúnaður er notaður sem hjálpartól í mörgum þekktum og útbreiddum hugbúnaði. Um er að ræða Java hugbúnað sem finnst á fjölmörgum stöðum á internetinu og innan fyrirtækja.

Þann 16 desember 2021 var opinberaður annar veikleiki [CVE-2021-45105](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45105) sem fær CVSS skorið 7.5 af 10. Þessi veikleiki getur kæft (DDoS) hugbúnað byggðan á Log4J þannig að hann hætti að virka. Gallinn er að finna í útgáfum 2.0-alpha1 til 2.16.0. Mælt er með að uppfæra í 2.17.0. 

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
* [CVE-2021-45105](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45105)
* [Fjarskiptastofa – Netöryggssveitin CERT-IS hefur virkjað samhæfingarferli vegna alvarlegs veikleika í algengum hugbúnaði](https://www.fjarskiptastofa.is/fjarskiptastofa/tolfraedi-og-gagnasafn/frettasafn/frett/fr%C3%A9ttir/netoryggssveitin-cert-is-hefur-virkjad-samhaefingarstod-vegna-alvarlegs-veikleika-i-algengum-hugbunadi)

### Ráðleggingar eða yfirlýsingar íslenskum fyrirtækjum
* [Advania](https://www.advania.is/um-advania/frettaveita/efnisveita/frett/2021/12/13/Vidbragd-vid-Log4j-oryggisveikleikanum/)
* [Opin Kerfi](https://opinkerfi.is/vidbrogd-vid-log4j-veikleika-cve-2021-44228/)
* [Origo](https://www.origo.is/um-origo/frettir/alvarlegur-oryggisveikleiki)
* [Sensa](https://sensa.is/log4j2-veikleikinn/)
* [Síminn](https://www.siminn.is/frettir/vegna-log4j-veikleika)
* [Vodafone](https://vodafone.is/frettir/frettir/2021/12/16/Log4j-veikleiki-Unnid-i-samraemi-vid-aaetlanir/)
* [Wise](https://wise.is/2021/12/13/vidbragd-vid-log4j-oryggisveikleikanum-2/)
* [Þekking](https://www.thekking.is/oryggisveikleiki-i-java-kodasafni-log4shell)


### Ráðleggingar eða yfirlýsingar frá birgjum og hugbúnaðarframleiðendum

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
* [Ahsay](https://wiki.ahsay.com/doku.php?id=public__colon__announcement__colon__cve-2021-44228_log4j)
* [Solarwinds](https://www.solarwinds.com/trust-center/security-advisories/cve-2021-44228)

## Algengur hugbúnaður á íslandi

Hér er að finna lista yfir hugbúnað, búnað og kerfi sem eru algeng á Íslandi.

* **Í lagi** = Svo best sem vitað er inniheldur kerfið ekki veikleikann.
* **í lagi* ** = Svo best sem vitað er inniheldur kerfið ekki veikleikann en sjá athugasemd/heimild.
* **Berskjaldað** = Kerfið inniheldur veikleikann og mælt er með að kynna sér betur hvort að úrlausn sé komin.
* **Óvíst** = Óljóst er hvort að kerfið inniheldur veikleikann eða ekki.

?> Hlekkir undir **Heimild** eru tilvísanir í ráðleggingar eða skýringar frá framleiðanda. 

| Hugbúnaður | Staða | Uppfært | Athugasemd | Heimild |
| ---------- | ----- | ------- | ---------- | ------- |
|  Office 365 |  Í lagi       |  15.12.21  |  Microsoft telur að veikleikinn eigi ekki við.  | [Nánari upplýsingar](https://msrc-blog.microsoft.com/2021/12/11/microsofts-response-to-cve-2021-44228-apache-log4j2/       ) | 
|  Microsoft 365 |  Í lagi       |  15.12.21  |  Microsoft telur að veikleikinn eigi ekki við.  | [Nánari upplýsingar](https://msrc-blog.microsoft.com/2021/12/11/microsofts-response-to-cve-2021-44228-apache-log4j2/    ) | 
|  PowerBI |  Í lagi       |  15.12.21  |  Microsoft telur að veikleikinn eigi ekki við.  | [Nánari upplýsingar](https://msrc-blog.microsoft.com/2021/12/11/microsofts-response-to-cve-2021-44228-apache-log4j2/          ) | 
|  Minecraft |  Berskjaldað  |  15.12.21  |  Þarf að uppfæra í 1.18.1. Útgáfur undir 1.7 eru í lagi.  | [Nánari upplýsingar](https://help.minecraft.net/hc/en-us/articles/4416199399693-Security-Vulnerability-in-Minecraft-Java-Edition        ) | 
|  Unifi Video |  Berskjaldað  |  18.12.21  |  Ekki er í boði patch frá framleiðanda, kerfi komið úr stuðningi  | [Nánari upplýsingar](https://aikester.com/2021/addressing-the-log4j-vulnerability-in-unifi-video-3.10.13/ ) | 
|  Unifi Controller |  Berskjaldað  |  15.12.21  |  Komið út patch sem þarf að uppfæra í.  | [Nánari upplýsingar](https://community.ui.com/releases/UniFi-Network-Application-6-5-54/d717f241-48bb-4979-8b10-99db36ddabe1 ) | 
|  Cisco Webex Meetings Server  |  Bergskjaldað  |  15.12.21  |  Komið út fix CWMS-3.0MR4SP2 og CWMS-4.0MR4SP2 (CSCwa47283) |  | 
|  Cisco Identity Services Engine (ISE) |  Berskjaldað  |  15.12.21  |  Hotfix komið fyrir 2.4, 2.6, 2.7, 3.0 og 3.1 (CSCwa47133)  | [Nánari upplýsingar](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd) | 
|  Cisco AnyConnect Secure Mobility Client  |  Í lagi  |  15.12.21  |  Anyconnect client er í lagi  |  | 
|  Cisco Meraki  |  Í lagi  |  15.12.21  |  GO, MR, MS, MT, MV, MX, SM og Z-series  |  | 
|  Cisco Adaptive Security Appliance (ASA) & ASAv Software  |  Í lagi  |  15.12.21  |  ASA eldveggir í lagi  |  | 
|  Cisco Adaptive Security Device Manager  |  Í lagi  |  15.12.21  |  ASDM management viðmót í lagi  |  | 
|  Cisco Firepower Thread Defense (FTD) managed by Cisco Firepower Management Center  |  Í lagi  |  15.12.21  |   |  | 
|  Cisco Firepower Threat Defense (FTD) managed by Firepower Device Manager (FDM)  |  Berskjaldað  |  15.12.21  |  Cisco er að vinna að lausn (CSCwa46963)  |  | 
|  Cisco Nexus switches  |  Í lagi  |  15.12.21  |  Á við um 3000, 5500, 5600, 6000, 7000, 9000  |  | 
|  Cisco Aironet Access Points  |  Í lagi  |  15.12.21  |  Cisco aironet þráðlausir punktar  |  | 
|  Cisco Catalyst 9100 Series Access Points  |  Í lagi  |  15.12.21  |  Cisco catalyst 9100 þráðlausir punktar  |  | 
|  Cisco Catalyst 9800 Series Wireless Controllers  |  Í lagi  |  15.12.21  |  Cisco Catalyst 9800 þráðlausir controllerar  |  | 
|  Cisco IOS Access Points  |  Í lagi  |  15.12.21  |  Cisco IOS þráðlausir punktar  |  | 
|  Cisco DNA Center  |  Berskjaldað  |  15.12.21  |  Fix komið (CSCwa47322)  |  | 
|  Cisco Email Security Appliance (ESA)  |  Í lagi  |  15.12.21  |   |  | 
|  Cisco Web Security Appliance (WSA)  |  Í lagi  |  15.12.21  |   |  | 
|  Cisco Modeling Labs  |  Í lagi  |  15.12.21  |   |  | 
|  Cisco Duo Security  |  Í lagi  |  15.12.21  |  Innihélt veikleika, en leyst  |  | 
|  Cisco Umbrella DNS / SIG  |  Í lagi  |  15.12.21  |  Innihélt veikleika en leyst  |  | 
|  Cisco SecureX  |  Í lagi  |  15.12.21  |   |  | 
|  Cisco IOS and IOS XE Software  |  Í lagi  |  15.12.21  |   |  | 
|  Cisco IOS XR Software  |  Í lagi  |  15.12.21  |   |  | 
|  Cisco Webex Meetings  |  Í lagi  |  15.12.21  |  Innihélt veikleika, en leyst  |  | 
|  HPE SimpliVity  |  Berskjaldað  |  15.12.21  |  HPE vinnur að lausn  |  | 
|  HPE StoreServ Management Console (SSMC) All versions  |  Berskjaldað  |  15.12.21  |  HPE vinnur að lausn   |  | 
|  HPE Hyper Converged 380 All versions  |  Berskjaldað  |  15.12.21 |  |  | 
|  HPE 3PAR Service Processor All versions  |  Berskjaldað  |  15.12.21  |  HPE vinnur að lausn   |  | 
|  Nagios |  Í lagi  |  15.12.21  |  Nagios Core og Nagios XI  | [Nánari upplýsingar](https://www.nagios.com/news/2021/12/update-on-apache-log4j-vulnerability/ ) | 
|  Zabbix |  Í lagi  |  18.12.21  |  Vöktunarkerfið Zabbix  | [Nánari upplýsingar](https://blog.zabbix.com/zabbix-not-affected-by-the-log4j-exploit/17873/ ) | 
|  1Password |  Óvíst  |  15.12.21  |  Opinber tilkynning ekki komin, en gefið til kynna að það sé í lagi  | [Nánari upplýsingar](https://1password.community/discussion/comment/622615 ) | 
|  Citrix Hypervisor (XenServer) |  Í lagi  |  15.12.21  |  XenServer er í lagi  | [Nánari upplýsingar](https://support.citrix.com/article/CTX335705 ) | 
|  Citrix Virtual Apps and Desktops (XenApp & XenDesktop) |  Í skoðun  |  15.12.21  |  Er í greiningu hjá framleiðanda  | [Nánari upplýsingar](https://support.citrix.com/article/CTX335705 ) | 
|  Ahsay |  Bergskjaldað  |  15.12.21  |  AhsayCBS, AhsayOBM, AhsayACB, AhsayUBS 8.5.4.86 (og nýrra) og 7.17.2.2 (með hotfix 7.17.2.127+) og útgáfur undir 6.29.x) í lagi  | [Nánari upplýsingar](https://wiki.ahsay.com/doku.php?id=public__colon__announcement__colon__cve-2021-44228_log4j ) | 
|  TimeXtender |  Í lagi  |  15.12.21  |    | [Nánari upplýsingar](https://support.timextender.com/hc/en-us/articles/4413724826897-Apache-Log4j ) | 
|  MongoDB Atlas Search |  Berskjaldað  |  15.12.21  |    | [Nánari upplýsingar](https://www.mongodb.com/blog/post/log4shell-vulnerability-cve-2021-44228-and-mongodb ) | 
|  MongoDB aðrar vörur  |  Í lagi  |  15.12.21  |   |  | 
|  MariaDB |  Í lagi  |  15.12.21  |   | [Nánari upplýsingar](https://mariadb.com/resources/blog/log4shell-and-mariadb-cve-2021-44228/ ) | 
|  Amazon S3  |  Berskjaldað  |  15.21.21  |    |  | 
|  Solarwinds Server & Application Monitor |  Berskjaldað  |  15.12.21  |    | [Nánari upplýsingar](https://www.solarwinds.com/trust-center/security-advisories/cve-2021-44228 ) | 
|  Solarwinds Database Performance Analyzer |  Berskjaldað  |   15.12.21  |   | [Nánari upplýsingar](https://www.solarwinds.com/trust-center/security-advisories/cve-2021-44228 ) | 
|  Solarwinds Orion Platform  |  Í lagi  |  15.12.21  |    |  | 
|  Enghouse QMS |  Berskjaldað  |  16.12.21  |   | [Nánari upplýsingar](https://github.com/opinkerfi/log4j/blob/560ff977d620513bf82f4eea15b4d863736bc9b1/docs/EXTERNAL_QMS_Enghouse_Log4j_vulnerability_statement_131221.pdf ) | 
|  Tableau / Tableau Reader, Tableau Public Desktop Client |  Berskjaldað  |  16.12.21  |   | [Nánari upplýsingar](https://kb.tableau.com/articles/issue/Apache-Log4j2-vulnerability-Log4shell ) | 
|  ATlassian Bitbucket Server  |  Berskjaldað  |  16.12.21  |   |  | 
|  Atlassian Confluence  |  Í lagi  |  16.12.21  |   |  | 
|  Atlassian Jira  |  Í lagi  |  16.12.21  |   |  | 
|  Splunk viðbætur |  Berskjaldað  |  16.12.21  |   | [Nánari upplýsingar](https://www.splunk.com/en_us/blog/bulletins/splunk-security-advisory-for-apache-log4j-cve-2021-44228.html ) | 
|  Jenksins |  Í lagi  |  16.12.21  |  Jenksins er í lagi, en skoða þarf viðbætur sérstaklega vel  | [Nánari upplýsingar](https://www.jenkins.io/blog/2021/12/10/log4j2-rce-CVE-2021-44228/ ) | 
|  Discord  |  óvíst  |  16.12.21  |   |  | 
|  Apache Kafka |  Í lagi  |  16.12.21  |   | [Nánari upplýsingar](https://kafka.apache.org/cve-list ) | 
|  Plex |  Í lagi*  |  18.12.21  |  Formlega tilkynningu vantar frá framleiðanda  | [Nánari upplýsingar](https://www.reddit.com/r/PleX/comments/rdolem/the_internet_is_on_fire_with_this_log4j/ ) | 
|  Plesk |  Í lagi  |  16.12.21  |  | [Nánari upplýsingar](https://support.plesk.com/hc/en-us/articles/4412182812818-CVE-2021-44228-vulnerability-in-log4j-package-of-Apache ) | 
|  Red Hat Enterprise Linux |  Í lagi*  |  19.12.21  |  Red Hat Linux er í lagi, en mælt er með að keyra update  | [Nánari upplýsingar](https://access.redhat.com/security/vulnerabilities/RHSB-2021-009 ) | 
|  Red Hat Ansible  |  Í lagi  |  19.12.21  |   |  | 
|  Red Hat ýmsar vörur |  Í lagi  |  19.12.21  |  m.a. Certificate Sysetm, Directory Server, CloudForms, Satellite, Ceph, Gluster, Openstack platform (fyrir utan 13), RHEV  | [Nánari upplýsingar](https://access.redhat.com/security/vulnerabilities/RHSB-2021-009 ) | 
|  Red Hat ýmsar vörur |  Berskjaldað  |  19.12.21  |  m.a. Red Hat Enterprise Application Platform 7, Openshift 4, Openshift 3.11, Fuse, OpenShift Logging, Openstack Platform 13, Process Automation Manager  | [Nánari upplýsingar](https://access.redhat.com/security/vulnerabilities/RHSB-2021-009 ) | 
|  Elasticserach |  Berskjaldað  |  19.12.21  |   | [Nánari upplýsingar](https://discuss.elastic.co/t/elasticsearch-5-0-0-5-6-10-and-6-0-0-6-3-2-log4j-cve-2021-44228-cve-2021-45046-remediation/292054 ) | 
|  Zammad |  Berskjaldað  |  19.12.21  |  Verkbeiðnakerfið Zammad nýtir elasticsearch  | [Nánari upplýsingar](https://community.zammad.org/t/cve-2021-44228-cve-2021-45046-elasticsearch-users-be-aware/8256 ) | 
|  Datto  | Í lagi  |  20.12.21  |  Sem dæmi Autotask og aðrar datto vörur  |  [Nánari upplýsingar](https://www.datto.com/blog/dattos-response-to-log4shell) |
|  3CX  |  Í lagi  |  21.12.21  |  3CX hugbúnaður virðist vera í lagi  |  [Nánari upplýsingar](https://www.3cx.com/community/threads/log4j-vulnerability-cve-2021-44228.86436/#post-407911) |
|  7-Zip  |  Í lagi  |  21.12.21  |   |  [Mánari upplýsingar](https://sourceforge.net/p/sevenzip/discussion/45797/thread/b977bbd4d1/)  |
|  Activestate  |  Í lagi  |  21.12.21  |   |  [Nánari upplýsingar](https://www.activestate.com/blog/activestate-statement-java-log4j-vulnerability/)  |
|  Audiocodes  |  Berskjaldað  |  21.12.21  |  ARM og SmartTap eru berskjaldað og mælt með að uppfæra. Aðrar í lagi  |  [Nánari upplýsingar](https://services.audiocodes.com/app/answers/kbdetail/a_id/2225)  | 

## Um þessa síðu

Þessi síða er styrkt af Opnum Kerfum og er viðhaldið af starfsfólki Opinna Kerfa. Ef þú ert með athugasemd eða upplýsingar sem þú vilt sjá á þessari síðu þá er það velkomið að senda inn breytingar og viðbætur.


### Get ég hjálpað?

Öllum er frjálst að leggja til breytingar á þessari síðu. Ef þú vilt leggja lið, þá mælum við með eftirfarandi verklagi:

1. Forka [log4j](https://github.com/opinkerfi/log4j) kóðahirsluna inn á github
2. Uppfæra efni á forsíðu eða stofna aðrar síður.
3. Framkvæma breytingar á forsíðu `docs/Readme.md` eða með því að stofna aðrar síður undir `docs/`
4. Búa til pull request sem verður yfirfarið.

?> Síðan er skjöluð í markdown texta og birt gegnum [Docsify](https://docsify.js.org). Ef þú ert ekki kunnug(ur) Markdown þá má sjá dæmi um rithátt [hér](https://www.markdownguide.org/cheat-sheet/)
