# DBKK Organic Waste Segregation & Diversion System

A local V1 demo system for DBKK's organic-first, recyclable-aware waste workflow.

It covers:

- role-based login for DBKK Admin, Vendor, and Collector / Compost Operator
- waste source registry
- segregation compliance inspections
- organic pickup requests and schedule tracking
- actual collection records with contamination notes
- compost destination and intake confirmation
- compost output tracking
- lightweight recyclable records
- dashboard KPIs and CSV reports

## Run It

Open PowerShell in this folder:

```powershell
cd "C:\Users\irene\Desktop\waste"
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

No package installation is required. The app uses only Python's standard library and SQLite.

## Demo Accounts

All demo users use this password:

```text
password123
```

| Role | Email |
| --- | --- |
| DBKK Admin | admin@dbkk.local |
| Vendor | vendor@dbkk.local |
| Collector / Compost Operator | collector@dbkk.local |

## Data

The SQLite database is created automatically at:

```text
data\dbkk_organic.db
```

To reset the seeded demo data, stop the app, delete `data\dbkk_organic.db`, and run `python app.py` again.

## V1 Boundary

This is intentionally not a full citywide solid waste system. It focuses on the V1 requirements:

- register organic waste generators
- monitor compostable and recyclable segregation
- manage separate organic pickup and collection
- confirm compost-site intake
- record compost output
- report landfill diversion and participation performance
