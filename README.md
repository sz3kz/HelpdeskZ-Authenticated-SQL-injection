# HelpdeskZ-Authenticated-SQL-injection
HelpDeskZ &lt; 1.0.2 Authenticated SQL Injection (updated for current python)

## Setup
1) Open a virtual python environment
```bash
python3 -m venv myvenv
source myvenv/bin/activate
```
2) Install requirements
```bash
pip install -r requirements.txt
```

## Usage
```bash
./helpdeskz-sql-injection.py --help
```
Most probably you want to run the script with default table and column values, so you need only specify the url, email and password.
For example:
```bash
./helpdeskz-sql-injection.py http://aid.htb/assistance/ aidme@aidme.com godaidmecouldyou
```

## Deletion
1) Exit out of the virtual python environment
```bash
deactivate
```
2) Delete the python virtual environment
```bash
rm -r myvenv/
``` 
3) Delete git directory
```bash
rm -rf HelpdeskZ-Authenticated-SQL-injection/
```
