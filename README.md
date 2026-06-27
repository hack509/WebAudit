# WebAudit 🔍

**Professional Web Application Auditing Tool**

WebAudit est un outil Python modulaire capable d'auditer automatiquement une application web.
Il combine les fonctionnalités de SonarQube, Lighthouse, Postman, Playwright et OWASP Scanner
dans un seul outil en ligne de commande.

**Développé par Desulma Jhonsley.**

---

## ✨ Fonctionnalités

| Module | Description |
|--------|-------------|
| 🔎 **Découverte** | Détection automatique des frameworks, serveurs, versions |
| 🔧 **Backend** | Test des routes, headers, CORS, compression, rate limiting |
| 🌐 **API** | Test de tous les verbes HTTP, payloads, injections, charge |
| 🎨 **Frontend** | Scan des pages, liens cassés, images, formulaires, SEO, PWA |
| 🔒 **Sécurité** | OWASP Top 10, XSS, SQL Injection, CSRF, secrets exposés |
| ⚡ **Performance** | TTFB, LCP, CLS, FID, cache, compression, bundle sizes |
| 🎯 **UX** | Contraste, touch targets, overflow, texte coupé, images déformées |
| 📜 **JavaScript** | Console errors, warnings, memory leaks, deprecated APIs |
| 🔑 **Auth** | Login, registration, JWT, session, brute force, OAuth |
| 🗄️ **Base de données** | Connexion, schéma, indexes, contraintes (PostgreSQL, MySQL, SQLite) |
| 📱 **Mobile** | Responsive, viewport, safe area, touch targets, orientation |
| 🧪 **E2E** | Tests Playwright : navigation, auth, formulaires, recherche |
| 📸 **Screenshots** | Captures Desktop, Tablet, Mobile |
| 📊 **Rapports** | HTML, PDF, JSON, CSV, Markdown (FR/EN) |

---

## 🚀 Installation

### Prérequis

- Python 3.10+
- pip

### Installation

```bash
# Cloner le projet
cd webAudit

# Créer un environnement virtuel
python -m venv venv

# Activer l'environnement (Windows)
venv\Scripts\activate

# Activer l'environnement (Linux/macOS)
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt

# Installer Playwright et ses navigateurs
playwright install chromium
```

---

## 📖 Utilisation

### Mode interactif

```bash
python main.py
```

Un menu interactif s'affiche :

```
 ╔══════════════════════════════════════╗
 ║       📋 Menu Principal              ║
 ╠══════════════════════════════════════╣
 ║   1  Audit complet                   ║
 ║   2  Audit Backend                   ║
 ║   3  Audit Frontend                  ║
 ║   4  Audit API                       ║
 ║   5  Audit Sécurité                  ║
 ║   6  Audit Performance               ║
 ║   7  Audit UX                        ║
 ║   8  Audit JavaScript                ║
 ║   9  Audit Mobile                    ║
 ║  10  Audit Authentification          ║
 ║  11  Audit Base de données           ║
 ║  12  Tests End-to-End                ║
 ║  13  Captures d'écran                ║
 ║  14  Générer rapport                 ║
 ║  15  Configuration                   ║
 ║   0  Quitter                         ║
 ╚══════════════════════════════════════╝
```

### Mode CLI direct

```bash
# Audit complet
python main.py --url https://example.com

# Audit avec JWT
python main.py --url https://api.example.com --token eyJhbGciOiJ...

# Audit avec credentials
python main.py --url https://example.com --user admin --password secret

# Modules spécifiques
python main.py --url https://example.com --module security performance

# Configuration JSON
python main.py --config config/default_config.json

# Choix du format de rapport
python main.py --url https://example.com --format html pdf json csv markdown

# Rapport en anglais
python main.py --url https://example.com --lang en

# Mode verbose
python main.py --url https://example.com --verbose
```

---

## ⚙️ Configuration

### Fichier JSON

Créez un fichier de configuration (voir `config/default_config.json`) :

```json
{
  "target": {
    "url": "https://example.com",
    "api_base": "/api/v1"
  },
  "auth": {
    "jwt_token": "eyJhbG...",
    "username": "admin",
    "password": "secret"
  },
  "database": {
    "connection_string": "postgresql://user:pass@localhost/dbname"
  },
  "report": {
    "formats": ["html", "json", "pdf"],
    "language": "fr"
  }
}
```

### Options CLI

| Option | Description |
|--------|-------------|
| `--url` | URL cible à auditer |
| `--source` | Chemin vers le code source |
| `--token` | Token JWT pour l'authentification |
| `--user` | Nom d'utilisateur |
| `--password` | Mot de passe |
| `--config` | Fichier de configuration JSON |
| `--output` | Répertoire de sortie des rapports |
| `--format` | Formats de rapport (html, pdf, json, csv, markdown) |
| `--module` | Modules spécifiques à exécuter |
| `--lang` | Langue des rapports (fr, en) |
| `--verbose` | Mode verbeux |

---

## 🏗️ Architecture

```
webAudit/
├── main.py                    # Point d'entrée CLI
├── requirements.txt           # Dépendances
├── config/
│   ├── settings.py           # Modèles de configuration (Pydantic)
│   └── default_config.json   # Configuration par défaut
├── utils/
│   ├── logger.py             # Logging centralisé (Rich)
│   ├── http_client.py        # Client HTTP (sync + async)
│   ├── helpers.py            # Fonctions utilitaires
│   ├── constants.py          # Constantes (payloads, signatures)
│   └── scoring.py            # Moteur de scoring
├── audit/
│   ├── base.py               # BaseAuditor (classe abstraite)
│   ├── result.py             # Modèles de données (findings, results)
│   ├── runner.py             # Orchestrateur d'audit
│   ├── discovery/            # Module 1 — Découverte
│   ├── backend/              # Module 2 — Backend
│   ├── api/                  # Module 3 — API
│   ├── frontend/             # Module 4 — Frontend
│   ├── ux/                   # Module 5 — UX
│   ├── performance/          # Module 6 — Performance
│   ├── javascript/           # Module 7 — JavaScript
│   ├── security/             # Module 8 — Sécurité
│   ├── auth/                 # Module 9 — Authentification
│   ├── database/             # Module 10 — Base de données
│   ├── mobile/               # Module 11 — Mobile
│   ├── e2e/                  # Module 12 — E2E
│   └── screenshots/          # Module 13 — Screenshots
├── reports/
│   └── generator.py          # Module 14 — Rapports
├── screenshots/              # Captures d'écran (sortie)
├── logs/                     # Fichiers de log
└── tests/                    # Tests unitaires
```

---

## 📊 Scoring

Chaque module produit un score de **0 à 100**. Le score global est une **moyenne pondérée** :

| Module | Poids |
|--------|-------|
| Sécurité | 20% |
| Performance | 15% |
| Backend | 15% |
| API | 10% |
| Frontend | 10% |
| UX | 10% |
| Accessibilité | 5% |
| SEO | 5% |
| JavaScript | 5% |
| Mobile | 5% |

### Grades

| Score | Grade |
|-------|-------|
| 90-100 | A 🟢 |
| 80-89 | B 🟢 |
| 70-79 | C 🟡 |
| 60-69 | D 🟠 |
| 50-59 | E 🔴 |
| 0-49 | F 🔴 |

---

## 🔒 Sécurité

WebAudit effectue des tests de sécurité **non destructifs** :

- ✅ Lecture seule (pas de modification de données)
- ✅ Payloads de test inoffensifs
- ✅ Respect de `robots.txt` (configurable)
- ⚠️ À utiliser uniquement sur vos propres applications
- ⚠️ Ne pas utiliser sur des systèmes en production sans autorisation

---

## 🤝 Contribution

1. Fork le projet
2. Créer une branche (`git checkout -b feature/nouveau-module`)
3. Commit (`git commit -m 'Ajout nouveau module'`)
4. Push (`git push origin feature/nouveau-module`)
5. Pull Request

---

## 📝 Licence

MIT License — Libre d'utilisation, modification et distribution.

---

## 🙏 Crédits

Construit avec :
- [Playwright](https://playwright.dev/) — Browser automation
- [Rich](https://rich.readthedocs.io/) — Terminal UI
- [Pydantic](https://pydantic-docs.helpmanual.io/) — Data validation
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) — HTML parsing
- [SQLAlchemy](https://www.sqlalchemy.org/) — Database inspection
- [fpdf2](https://pyfpdf.github.io/fpdf2/) — PDF generation
