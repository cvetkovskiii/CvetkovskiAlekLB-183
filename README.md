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

### Rückblick
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
Das Artefakt hat eine SQL-Injektion Sicherheitslücke, das heisst, dass es aus den Eingaben direkt ein SQL String erstellt wird, das hat zur Folge, dass der SQL String nach Belieben verändert werden kann. Wie z.B "'; DROP TABLE *; --". Um dies zu verhindern, habe ich direkt den User gefiltert, anstatt einen String zu machen. 

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

### Rückblick
Meiner Meinung nach wurde mein Artefakt erfolgreich umgesetzt, da es eine Umsetzung mit einer Sicherheitslücke zeigt und gleichzeitig Lösungsansätze zur Verbesserung aufzeigt. Es konzentriert sich zwar nur auf die Darstellung von Injection, obwohl es noch zahlreiche andere potenzielle Sicherheitslücken gibt. Dennoch halte ich es für entscheidend, Injection zu verhindern, und es genügt meiner Ansicht nach, nicht jede Sicherheitslücke im Artefakt explizit zu behandeln.

## Handlungsziel 3: Mechanismen für die Authentifizierung und Autorisierung umsetzen können
### Artefakt


### Erklärung


### Handlungszielerreichung


### Rückblick

## Handlungsziel 4: Sicherheitsrelevante Aspekte bei Entwurf, Implementierung und Inbetriebnahme berücksichtigen
### Artefakt


### Erklärung


### Handlungszielerreichung


### Rückblick

## Handlungsziel 5: Informationen für Auditing und Logging generieren & Auswertungen und Alarme definieren und implementieren
### Artefakt


### Erklärung


### Handlungszielerreichung


### Rückblick
