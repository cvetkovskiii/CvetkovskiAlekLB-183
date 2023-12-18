# Applikationssicherheit: Erfahrungen, Risiken & Schutz
Alek Cvetkovski | LB-183

## Einleitung
Willkommen zu meinem Portfolio, das einen tiefen Einblick in meine Entwicklungen und Erlebnisse im Bereich der Applikationssicherheit gewährt. Hier finden Sie eine gründliche Untersuchung aktueller Bedrohungen, das Aufspüren und Schließen von Sicherheitslücken, die Integration von Mechanismen zur Authentifizierung und Autorisierung, die Beachtung sicherheitsrelevanter Aspekte sowohl im Entwurfs- als auch im Implementierungsprozess sowie die Generierung von Informationen für Auditing und Logging. Tauchen Sie ein und entdecken Sie meine Reise durch die Welt der Sicherheit im Code.

## Handlungsziel 1: Aktuelle Bedrohungen erkennen und erläutern können
### Artefakt
LA_183_04_Grundbegriffe (1).docx

### Erklärung
Das Artefakt bietet eine Bewertung von fünf Sicherheitsszenarien in Bezug auf die Schutzziele. Die Bewertung erfolgt auf einer Skala von 0 bis 2, wobei 0 für "gar nicht", 1 für "teilweise" und 2 für "erheblich" steht. Darüber hinaus enthält es eine Untersuchung der wichtigsten Sicherheitsrisiken für eine Webapplikation mithilfe der OWASP-Richtlinien. 

### Handlungszielerreichung
Ich habe das Handlungsziel erreicht, da das Artefakt eine umfassende Analyse verschiedener Sicherheitsszenarien enthält und deren Auswirkungen auf die Schutzziele Vertraulichkeit, Integrität und Verfügbarkeit aufzeigt.

### Beurteilung
Die Umsetzung des Artefakts war erfolgreich, da es eine detaillierte Analyse der Sicherheitsszenarien bietet und die Auswirkungen auf die Schutzziele bewertet. Es ermöglicht eine fundierte Beurteilung der Bedrohungen in Bezug auf Vertraulichkeit, Integrität und Verfügbarkeit. Durch die Berücksichtigung von OWASP-Richtlinien wird zudem ein umfassender Einblick in aktuelle Sicherheitspraktiken gewährleistet.

## Handlungsziel 2: Sicherheitslücken und ihre Ursachen in einer Applikation erkennen können
### Artefakt 
BEFORE:

        public ActionResult<User> Login(LoginDto request)
        {
            if (request == null || request.Username.IsNullOrEmpty() || request.Password.IsNullOrEmpty())
            {
                return BadRequest();
            }

            string sql = string.Format("SELECT * FROM Users WHERE username = '{0}' AND password = '{1}'", 
                request.Username, 
                MD5Helper.ComputeMD5Hash(request.Password));

            User? user= _context.Users.FromSqlRaw(sql).FirstOrDefault();
            if (user == null)
            {
                return Unauthorized("login failed");
            }
            return Ok(user);
        }

### Erklärung
Das Artefakt weist eine Sicherheitslücke in Form einer SQL-Injektion auf. Dies bedeutet, dass aus den Benutzereingaben direkt ein SQL-String erstellt wird, was zur Folge hat, dass der SQL-String nach Belieben verändert werden kann. Ein Beispiel hierfür wäre "'; DROP TABLE *; --". Um dieser Problematik vorzubeugen, habe ich nun eine direkte Benutzerfilterung implementiert, anstatt einen reinen String zu generieren.

AFTER: 

          public ActionResult<User> Login(LoginDto request)
         {
            if (request == null || request.Username.IsNullOrEmpty() || request.Password.IsNullOrEmpty())
            {
                return BadRequest();
            }

            string username = request.Username;
            string passwordHash = MD5Helper.ComputeMD5Hash(request.Password);

            User? user = _context.Users
                .Where(u => u.Username == username)
                .Where(u => u.Password == passwordHash)
                .FirstOrDefault();

            if (user == null)
            {
                return Unauthorized("login failed");
            }
            return Ok(user);
         }

### Handlungszielerreichung
Ich habe dieses Handlungsziel erreicht, indem ich  anhand von einem Beispiel eine Sicherheitslücke gezeigt habe (BEFORE-Code) und eine mögliche Gegenmassnahme mit Implementierung aufgezeigt habe (AFTER-Code).

### Beurteilung
Meiner Meinung nach wurde mein Artefakt erfolgreich umgesetzt, da es eine Umsetzung mit einer Sicherheitslücke zeigt und gleichzeitig Lösungsansätze zur Verbesserung aufzeigt. Es konzentriert sich zwar nur auf die Darstellung von Injection, obwohl es noch zahlreiche andere potenzielle Sicherheitslücken gibt. Dennoch halte ich es für entscheidend, Injection zu verhindern, und es genügt meiner Ansicht nach, nicht jede Sicherheitslücke im Artefakt explizit zu behandeln.

## Handlungsziel 3: Mechanismen für die Authentifizierung und Autorisierung umsetzen können
### Artefakt

     private string CreateToken(User user)
     {
        string issuer = _configuration.GetSection("Jwt:Issuer").Value!;
        string audience = _configuration.GetSection("Jwt:Audience").Value!;

     List<Claim> claims = new List<Claim>
     {
         new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
         new Claim(JwtRegisteredClaimNames.NameId, user.Id.ToString()),
         new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
         new Claim(ClaimTypes.Role,  (user.IsAdmin ? "admin" : "user"))
     };

     if (IsUserAuthorized(user, "admin"))
     {
         claims.Add(new Claim(ClaimTypes.Role, "admin"));
     }

     string base64Key = _configuration.GetSection("Jwt:Key").Value!;
     SymmetricSecurityKey securityKey = new SymmetricSecurityKey(Convert.FromBase64String(base64Key));

     SigningCredentials credentials = new SigningCredentials(
        securityKey,
        SecurityAlgorithms.HmacSha512Signature);

     JwtSecurityToken token = new JwtSecurityToken(
         issuer: issuer,
         audience: audience,
         claims: claims,
         notBefore: DateTime.Now,
         expires: DateTime.Now.AddDays(1),
         signingCredentials: credentials
     );

     return new JwtSecurityTokenHandler().WriteToken(token);
     }

     private bool IsUserAuthorized(User user, string requiredRole)
     {
     return user.IsAdmin;
     }



### Erklärung
#### Authentifizierung
Hier sieht man die Implementierung der Erstellung eines JSON Web Tokens (JWT) als Mechanismus zur Authentifizierung. Als eine URL-sichere Methode ermöglicht ein JWT den Austausch von Informationen zwischen Parteien. In diesem Kontext dient der JWT der Authentifizierung eines Benutzers. Im Allgemeinen werden JWTs verwendet, um bei wiederholten Anfragen an den Server zu prüfen, ob der Benutzer berechtigt ist, ohne dabei jedes Mal die Benutzerdaten erneut abzufragen.

#### Autorisierung
Die Methode IsUserAuthorized repräsentiert einen Teil der Autorisierung. Sie wird aufgerufen, um zu überprüfen, ob der Benutzer autorisiert ist. Hier wird die Rolle "admin" zum Token hinzugefügt, wenn die Methode IsUserAuthorized dies bestätigt.

### Handlungszielerreichung
Die Umsetzung des Handlungsziels wurde erreicht, indem die Authentifizierung durch die JWT-Erstellung und die Autorisierung durch die Überprüfung der Benutzerberechtigungen implementiert wurden. Die Autorisierung wird hier anhand der Benutzerrolle "admin" behandelt.

### Beurteilung
Die Zielsetzung wurde erfolgreich erreicht, indem sowohl Authentifizierungs- als auch Autorisierungsmechanismen implementiert wurden. Die Verwendung von JWTs ermöglicht eine sichere Identifizierung von Benutzern, während die Autorisierung sicherstellt, dass bestimmte Aktionen nur von autorisierten Benutzern durchgeführt werden können. Obwohl das Beispiel sich auf die Rolle "admin" konzentriert, bietet die Struktur Raum für eine erweiterte Rollenverwaltung, um unterschiedliche Berechtigungen zu unterstützen.

## Handlungsziel 4: Sicherheitsrelevante Aspekte bei Entwurf, Implementierung und Inbetriebnahme berücksichtigen
### Artefakt
![image](https://github.com/cvetkovskiii/CvetkovskiAlekLB-183/assets/91133679/60326e9f-c71b-4481-82c4-34465238d1af)

### Erklärung
#### Eingabevalidierung: 
##### Mailadresse muss ein «@» beinhalten
Sicherheitsmaßnahme, um sicherzustellen, dass Benutzereingaben für E-Mail-Adressen das "@"-Zeichen enthalten und grundlegende Formatanforderungen erfüllen.

##### SQL-Injection (SQL-I)
Präventive Maßnahme gegen SQL-Injection-Angriffe, indem Benutzereingaben sicher in SQL-Abfragen integriert werden, um unautorisierten Datenbankzugriff zu verhindern.

#### Ausgabevalidierung: 
##### XSS (Cross-Site Scripting)
Schutzmaßnahme, um Benutzereingaben so zu filtern und zu kodieren, dass schädlicher Code nicht in Webseiten eingeschleust und im Browser des Benutzers ausgeführt werden kann.

### Sessionhandling: 
##### Zufällige IDs
Sicherheitspraxis, bei der Sitzungs-IDs zufällig generiert werden, um vorhersehbare Sitzungen zu verhindern und somit das Risiko von Sitzungsübernahmen zu minimieren.

### Errorhandling: 
##### Keine Ausgabe von internen Daten
Sicherheitsrichtlinie, die sicherstellt, dass bei auftretenden Fehlern keine sensiblen internen Informationen in Fehlermeldungen preisgegeben werden, um das Sicherheitsrisiko zu minimieren.

### Vermeiden von Risiken: 
#### Möglichst wenig externe Libraries verwenden
Sicherheitsstrategie, die darauf abzielt, das Angriffsoberfläche zu minimieren und das Risiko von Sicherheitslücken durch die Reduzierung externer Bibliotheken zu verringern.

#### Kein Administrationsinterface auf dem Web
Schutzmaßnahme, bei der administrative Funktionen nicht über das öffentliche Internet zugänglich sind, um unautorisierten Zugriff und potenzielle Angriffe zu verhindern.

### Architektur: 
#### Mehrschichtiges Sicherheitssystem
Sicherheitskonzept, das auf verschiedenen Ebenen der Anwendung mehrere Sicherheitsmechanismen implementiert, um vor verschiedenen Arten von Angriffen zu schützen.

#### Security by Default
Designprinzip, bei dem Sicherheitsfunktionen integraler Bestandteil der Anwendung sind, ohne dass zusätzliche Konfigurationen erforderlich sind, um die Wahrscheinlichkeit von Sicherheitslücken zu minimieren.

#### Möglichst wenig externe Libraries verwenden

Sicherheitsrichtlinie, die darauf abzielt, das Risiko von Sicherheitslücken durch externe Abhängigkeiten zu verringern, indem die Anzahl der verwendeten externen Bibliotheken minimiert wird.

### Handlungszielerreichung


### Beurteilung

## Handlungsziel 5: Informationen für Auditing und Logging generieren & Auswertungen und Alarme definieren und implementieren
### Artefakt


### Erklärung


### Handlungszielerreichung


### Beurteilung
