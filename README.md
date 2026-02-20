🫧 GlassPins

Pinterest-style mini social in PHP puro (1 solo file) con:

✨ UI stile Liquid Glass (Apple vibe)

📱 Completamente responsive (mobile-first)

👤 Sistema Account (Register / Login / Logout)

🧑‍💼 Primo utente = Admin automatico

🖼 Upload immagini (JPG / PNG / WEBP)

🧱 Layout Masonry tipo Pinterest

🔍 Ricerca + filtro per tag

🧩 Dashboard personale con preview live

🛡 CSRF protection

🗃 Database SQLite automatico

Tutto in un unico file: index.php.

📂 Struttura Progetto
/project-folder
│
├── index.php        ← TUTTO IL SITO
├── data.sqlite      ← Creato automaticamente
├── uploads/         ← Foto caricate
└── README.md

Non serve altro.

⚙️ Requisiti

PHP 8.0+

Estensione SQLite abilitata (di solito già attiva)

Server locale (XAMPP, MAMP, Laragon, ecc.)

🚀 Installazione

Metti index.php in una cartella del tuo server

Avvia Apache

Apri nel browser:

http://localhost/tuacartella/

Il database viene creato automaticamente al primo avvio.

👤 Sistema Account
Registrazione

Vai su Crea account

Il primo utente registrato diventa ADMIN automaticamente

Password salvate con password_hash()

Login

Accesso tramite username + password.

Logout

Distrugge la sessione in modo sicuro.

🧑‍💼 Admin

L’admin può:

Eliminare QUALSIASI pin

Accedere alla pagina ?admin=1

Gestire tutto il feed

Gli utenti normali possono:

Creare pin

Eliminare solo i propri pin

🖼 Creazione Pin

Disponibile nella Bacheca (?dashboard=1)

Campi:

Foto (max 8MB)

Titolo

Descrizione

Tag (separati da virgola o spazio)

✨ Preview Live

La preview si aggiorna mentre scrivi.

🔍 Funzioni Feed

Layout masonry tipo Pinterest

Click su pin → Modal dettaglio

Copia link immagine

Ricerca per:

Titolo

Autore

Descrizione

Tag

Filtri per tag cliccabili

📱 Responsive

Mobile-first:

2 colonne su smartphone

3 colonne su tablet

4 colonne su desktop

Header sticky + effetto glass.

🛡 Sicurezza

CSRF token su tutte le POST

Validazione MIME reale con finfo

Limit upload 8MB

Password hashate

Sanitizzazione output (htmlspecialchars)

Upload limitati alla cartella uploads/

🎨 UI / Design

Stile:

Liquid Glass (blur + gradienti morbidi)

Glow soft shadows

Rounded corners

Animazioni leggere

Modal con blur background

Ispirazione:

Apple VisionOS

iOS glass morphism

Pinterest grid layout

🔧 Personalizzazione
Cambiare limite upload

In alto nel file:

const MAX_UPLOAD_BYTES = 8 * 1024 * 1024;
Cambiare colori tema

Nel CSS root:

:root {
  --accent: ...
  --accent2: ...
}
📌 URL Principali
Pagina	URL
Feed	index.php
Register	?register=1
Login	?login=1
Dashboard	?dashboard=1
Admin	?admin=1
🧠 Architettura

Nessun framework

Nessun Composer

Nessun JS esterno

Nessuna dipendenza

Solo:

PHP

SQLite

Vanilla JS

CSS moderno

📈 Possibili Upgrade Futuri

Like system

Commenti

Follow utenti

Salva pin

Notifiche

Modal edit pin

Paginazione infinita

API REST

📜 Licenza

Puoi usare, modificare e migliorare liberamente.

Se vuoi ti preparo anche:

🧩 Versione PRO con like + commenti

🔥 Versione con salvataggio pin stile Pinterest

🌐 Versione multi-file strutturata MVC

🛒 Versione marketplace

📦 Versione deploy pronta per hosting

Dimmi che direzione vuoi e la evolviamo 🚀
