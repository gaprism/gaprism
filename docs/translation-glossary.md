# Translation glossary: German (Switzerland)

The voice, the spelling and the terms of the German text, so that one thing has one name on every
screen. [translation.md](translation.md) says how the catalogues work. The terms marked ✓ were
agreed with the owner of the product; the others were chosen while translating and are open to
change (change them here and in the catalogue together).

## Voice

- **Formal address (*Sie*)**, short sentences, in the voice of the English text: what happened and
  what to do. "Die E-Mail-Adresse oder das Passwort stimmt nicht. Prüfen Sie beide und versuchen
  Sie es erneut." ✓
- **Neutral wording for people**: *Person*, *Konto*, *wer …*; no stars, colons or double forms.
  Administrators are *Admins*. ✓
- **Buttons and links**: the verb in the infinitive, the object before it: *Anmelden*, *Scan
  starten*, *Als False Positive markieren*. ✓
- **Nouns are capitalised**, loanwords included: *Scan*, *Host*, *Assessment*, *False Positive*.

## Spelling and typography

- Swiss spelling: **`ss`, never `ß`** (*Strasse*, *aussen*, *Grösse*). Umlauts are written as
  umlauts. ✓ (a test refuses `ß`)
- Quotation marks are **«guillemets»** (‹single› inside); the apostrophe in a German sentence is
  rare, and where it is needed it is `’`. ✓
- **Dates and times stay ISO 8601 in UTC** (`2026-11-05 14:30 UTC`), and numbers stay plain with a
  decimal point. Nothing is localised. ✓
- A literal percent sign is written `%%` in a catalogue (see [translation.md](translation.md)).
- Keep every `%(name)s` placeholder as it is; the order of the words around it is yours.

## Terms

| English | Deutsch (CH) | Note |
|---|---|---|
| assessment | Assessment (das, Pl. Assessments) ✓ | the record of one vendor domain |
| scan | Scan (der, Pl. Scans) ✓ | *Scan starten*, *laufender Scan* |
| host / hostname | Host (Pl. Hosts) / Hostname ✓ | |
| domain / subdomain | Domain / Subdomain | |
| finding | Befund (der, Pl. Befunde) ✓ | |
| rule | Regel (Pl. Regeln) | |
| evidence | Nachweis (Pl. Nachweise) | what a finding rests on |
| check | Prüfung (Pl. Prüfungen) | the verb is *prüfen* |
| severity | Schweregrad ✓ | |
| Critical, High, Medium, Low, Informational | Kritisch, Hoch, Mittel, Niedrig, Information ✓ | |
| confidence | Konfidenz ✓ | *Hohe*, *Mittlere*, *Geringe Konfidenz*; *Konfidenz unbekannt* |
| open, accepted | Offen, Akzeptiert ✓ | to accept a finding: *einen Befund akzeptieren* |
| false positive | **False Positive** ✓ (das, Pl. False Positives) | stays English: *Als False Positive markiert* |
| reopen | Wieder öffnen | |
| decision | Entscheidung | |
| vendor | Anbieter ✓ | |
| breach (a public one) | Datenleck (Pl. Datenlecks) ✓ | |
| report | Bericht ✓ | |
| export | Export ✓ | |
| compare, history | Vergleichen (der Vergleich), Verlauf ✓ | |
| archive, restore | Archivieren (das Archiv), Wiederherstellen ✓ | |
| delete | Löschen | |
| label | Bezeichnung | |
| private, shared | Privat, Geteilt ✓ | shared = with everyone who is signed in |
| owner (of an assessment) | zuständige Person; column *Zuständig* | neutral, not *Eigentümer* |
| account | Konto (Pl. Konten) ✓ | |
| administrator | Admin (Pl. Admins) ✓ | |
| role | Rolle | |
| sign in, sign out | Anmelden, Abmelden ✓ | the noun is *Anmeldung* |
| password | Passwort | |
| email address | E-Mail-Adresse | |
| two-factor authentication | Zwei-Faktor-Authentifizierung ✓ | |
| authenticator app | Authenticator-App | |
| invitation, link | Einladung, Link | a reset link: *Link zum Zurücksetzen* |
| profile, picture | Profil, Bild | *Profilbild* |
| audit log | Audit-Protokoll | |
| data location | Datenstandort | |
| allowed area | erlaubter Bereich | the countries a team allows |
| address, network | Adresse (IP-Adresse), Netzwerk | |
| shared infrastructure | gemeinsam genutzte Infrastruktur | |
| queued, running, finished, cancelled, failed | in der Warteschlange, läuft, abgeschlossen, abgebrochen, fehlgeschlagen | |

## Phrases that look like terms

"Attribution" is not a term: the screen never prints it. These phrases are translated as
phrases ✓:

| English | Deutsch (CH) |
|---|---|
| Confirmed for this hostname | Für diesen Hostnamen bestätigt |
| Seen on the address only | Nur auf der Adresse gesehen |
| Shared infrastructure | Gemeinsam genutzte Infrastruktur |
| Whole domain | Ganze Domain |
| Host name listed (ports page) | Hostname aufgeführt |
| Address only (ports page) | Nur Adresse |
| 7. Data sources and attributions (report) | 7. Datenquellen und Quellenangaben |

## Kept in English

Protocol, record and product names are not translated: DNS, DNSSEC, TLS, HTTP, HTTPS, HSTS, CDN,
CVE, CVSS, EPSS, KEV, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, CAA, MX, NS, TXT, CNAME, RDAP, ASN,
*Certificate Transparency*, *security.txt*, *Port*, *Header*, *Cookie*, *Handshake*,
*Cipher Suite*, *Resolver*. Names of companies and services (Shodan, Mozilla HTTP Observatory,
Have I Been Pwned, DB-IP) stay as they are. German forms of them take the German ending or
article where one is needed (*die CVEs*, *der Resolver*).
