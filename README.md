# HelpdeskZ-Authenticated-SQL-injection
HelpDeskZ &lt; 1.0.2 Authenticated SQL Injection (updated for current python)

## Setup
1) Open a virtual python environment
```bash
python3 -m venv myvenv
```
```bash
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

## Note about usage
This script was not built to replace SQLmap. If you require a more sophisticated program to enumerate the database, I urge you to consider setting up SQLmap guided by [0xdf's Help box writeup](https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax).

The functionality of this script is limited and the query templates I used don't play well with certain tables. For example, I had a problem enumerating the 'information_schema.tables" table in order to learn the available tables in the database.

The option to specify different columns and table are merely added as a bonus.
