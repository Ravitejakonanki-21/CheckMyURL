# URL Checker

A full‑stack web application that analyses URLs for phishing, poor SSL/TLS hygiene, weak security headers, unsafe WHOIS signals, suspicious keywords, and ML-driven risk. The project pairs a Flask backend (Python 3.11) with a React + Vite frontend and ships with pre-trained ML assets and curated datasets.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Key Features](#key-features)
3. [Prerequisites](#prerequisites)
4. [Local Setup](#local-setup)
5. [Environment Variables](#environment-variables)
6. [Running the Apps](#running-the-apps)
7. [Testing](#testing)
8. [Project Structure](#project-structure)
9. [Troubleshooting](#troubleshooting)

---

## Architecture

| Layer      | Tech / Responsibilities |
| ---------- | ------------------------ |
| Frontend   | React 18, Vite, Tailwind; dashboard UI, modals, context, interactive pies/bars |
| Backend    | Flask API, services for SSL, WHOIS, IDN/ASCII, headers, keyword heuristics, ML scoring, caching |
| Data/Model | `DataFiles/` CSV corpora for heuristics/testing, Random Forest model `phishing_rf_phiusiil.pkl` |


## Key Features

- **Deep URL Scan** – orchestrates SSL, WHOIS, headers, IDN/ASCII, keyword and ML checks.
- **Security Headers Audit** – dedicated endpoint + UI to show missing vs present headers.
- **Risk Composition UI** – reactive pie/line charts and weighted scores for each factor.
- **Authentication-Ready** – JWT, bcrypt, Flask-Mail scaffolding for forgot/reset flows.
- **PDF Export** – client-side `jsPDF` export of scan summaries.
- **Caching** – lightweight simple-cache to short-circuit repeat scans.


## Prerequisites

- Python **3.11+**
- Node.js **18+** and npm
- MongoDB (optional but recommended; default connection string targets `mongodb://localhost:27017/`)
- OpenSSL (for local SSL inspections)


## Local Setup

1. **Clone the repo**
   ```bash
   git clone https://github.com/Sahana1255/url-checker.git
   cd url-checker
   ```

2. **Python virtualenv**
   ```bash
   python -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate
   pip install -r backend/services/requirements.txt
   ```

3. **Install frontend deps**
   ```bash
   cd frontend
   npm install
   cd ..
   ```


## Environment Variables

Copy `.env.example` (if provided) or create `.env` files. Minimum backend vars:

| Variable             | Description                               |
| -------------------- | ----------------------------------------- |
| `MAIL_USERNAME`      | SMTP username for notification emails     |
| `MAIL_PASSWORD`      | SMTP password or app password             |
| `JWT_SECRET_KEY`     | Secret for Flask JWT                      |
| `MONGO_URI` (opt.)   | Mongo connection string                   |

Frontend uses Vite’s `VITE_*` pattern only if you expose custom URLs; defaults hit `http://127.0.0.1:5001`.


## Running the Apps

### Backend
```bash
source venv/bin/activate
export FLASK_APP=backend/app.py
python backend/app.py   # serves on http://127.0.0.1:5001
```

### Frontend
```bash
cd frontend
npm run dev    # http://127.0.0.1:5173
```

The scanner UI expects the backend at `http://127.0.0.1:5001`. Adjust `frontend/src/pages/Scanner.jsx` if you want a different host/port.


## Testing

- **Backend smoke tests**
  ```bash
  source venv/bin/activate
  pytest backend/services/tests/smoke_test.py
  ```

- **Frontend lint/test**
  ```bash
  cd frontend
  npm run lint
  npm run test   # if tests are defined
  ```


## Project Structure

```
url-checker/
├── backend/
│   ├── app.py                # Flask entrypoint / API routes
│   └── services/             # SSL, WHOIS, ML, headers, caching, etc.
├── frontend/
│   ├── src/
│   │   ├── components/       # Charts, modals, cards
│   │   ├── pages/            # Scanner, Results, Statistics
│   │   └── utils/            # risk calculators, formatters
│   └── public/
├── DataFiles/                # CSV datasets for training/eval
├── Content/                  # Project notes, abstracts, reports
└── venv/                     # Python virtual environment (optional)
```


## Troubleshooting

- **Port 5001 already in use** – stop any running Flask process (`lsof -i :5001` then `kill <PID>`).
- **Security headers show “None detected”** – ensure backend check is reachable; the frontend normalizes header keys to lower-case before counting.
- **Pie chart totals differ from “Total Score”** – `securityCalculations.js` now aligns pie safe% with the weighted overall score; re-run `npm run dev` after changes.
- **ML model missing** – confirm `backend/services/phishing_rf_phiusiil.pkl` exists; otherwise run `backend/services/run_ml_standalone.py` to rebuild.

For additional details, browse the code or open an issue/PR in the GitHub repository.

---

Happy scanning!

