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
- dashboard-integrated Google Maps operations view for sources, pickups, compliance, and compost destinations

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

## Deploy It

This is a Python web app, so GitHub Pages will not run it. Use a Python web host such as Render.

Fast Render setup:

1. Go to `https://dashboard.render.com`
2. Click `New` > `Blueprint`
3. Connect the GitHub repo `J26-1/waste-management-system`
4. Choose branch `main`
5. Keep the default Blueprint path `render.yaml`
6. Click `Deploy Blueprint`

Render will run:

```text
python app.py
```

The app uses Render's `PORT` and the configured `HOST=0.0.0.0`.

Note: the free deployment uses temporary filesystem storage. Demo data is created automatically, but changes may reset after redeploys/restarts unless you add persistent storage and set `DATABASE_PATH`.

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

## Dashboard Operations Map

The admin dashboard uses Google Maps embed and search links, so no Google Cloud API key is required.

Waste sources and destinations include latitude and longitude fields. Edit these in:

- `Waste Sources`
- `Destinations`

The dashboard operations map shows colored source and compost-site markers. Clicking a marker opens the connected pickup attention, segregation, collection, route, and compost-site information.

## V1 Boundary

This is intentionally not a full citywide solid waste system. It focuses on the V1 requirements:

- register organic waste generators
- monitor compostable and recyclable segregation
- manage separate organic pickup and collection
- confirm compost-site intake
- record compost output
- report landfill diversion and participation performance
