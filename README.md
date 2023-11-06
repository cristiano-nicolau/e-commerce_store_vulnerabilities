# Vulnerabilities in software products

## 1. Group Members:

| NMec | Name | email | 
|:---: |:---|:---:|
| 108317 | Miguel Aido Miragaia      | [miguelmiragaia@ua.pt](https://github.com/Miragaia)              |
| 108536 | Cristiano Antunes Nicolau | [cristianonicolau@ua.pt](https://github.com/cristiano-nicolau)   |
| 107463 | Pedro Miguel Ribeiro Rei  | [pedrorrei@ua.pt](https://github.com/pedrorrei)                  |
| 97541  | Andre Lourenço Gomes      | [andregomes@ua.pt](https://github.com/andregomes04)              |

## 2. Repository Structures

- **app** - Insecure app
    * **backend** - backend script (controller.py)
    * **templates** - frontend scripts (.html)
    * **css** - stylesheet scripts (.css)
    * **scss** - stylesheet scripts (.scss)
    * **js** - javascript scripts (.js)
    * **images** - images (.png, .jpg, .svg, .gif)

- **app_sec** - Secure app
    * **backend** - backend script (controller.py)
    * **templates** - frontend scripts (.html)
    * **css** - stylesheet scripts (.css)
    * **scss** - stylesheet scripts (.scss)
    * **js** - javascript scripts (.js)
    * **images** - images (.png, .jpg, .svg, .gif)

- **analysis** - All documentation to support the project
    * **prints** - directory with all the prints taken for this project
    * **report** - directory with the report in .pdf  
        * [Report.pdf](/analyses/report/Report.pdf)
    * **vulnerabilities** - 
        * **CWE-79** - directory with the vulnerable and secure demonstrations
        * **CWE-80** - directory with the vulnerable and secure demonstrations
        * **CWE-89** - directory with the vulnerable and secure demonstrations
        * **CWE-262** - directory with the vulnerable and secure demonstrations
        * **CWE-256** - directory with the vulnerable and secure demonstrations
        * **CWE-521** - directory with the vulnerable and secure demonstrations
        * **CWE-306** - directory with the vulnerable and secure demonstrations
        * **CWE-20** - directory with the vulnerable and secure demonstrations
        * **CWE-286** - directory with the vulnerable and secure demonstrations
        * **CWE-260** - directory with the vulnerable and secure demonstrations

- **README.md** - Guideline document for the project

## 3. Description

- **Introduction:**
    - This project involves the creation of an online shop for DETI. The main aspect was that the project should be developed in two distinct views.
        * **Vulnerable App:** Functional online shop with vulnerabilities, icluding CWE-79 (Cross-Site Scripting) and CWE-89 (SQL Injection).
        * **Secure App:** Functional online shop without vulnerabilities.

- **Objectives** 
    - The principal objective is identifying and correcting vulnerabilities. 

- **Tecnologies**
    - The project was developed using the following technologies:
        * **Frontend:** HTML, CSS, Javascript
        * **Backend:** Python, Flask, SQLAlchemy
        * **Database:** SQLite


## 4. Vulnerabilities
- CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS), 
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting'), 
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'),
- CWE-262: Not Using Password Aging, 
- CWE-256: Plaintext Storage of a Password,
- CWE-260: Password in Configuration File 
- CWE-521: Weak Password Requirements, 
- CWE-306: Missing Authentication for Critical Function, 
- CWE-20: Improper Input Validation, 
- CWE-286: Incorrect User Management.


## 5. How to run

1. pip install -r requirements
2. Run the backend Server:
    - app: Directory: /app/backend "python3 controller.py"
    - app_sec: Directory: /app_sec/backend "python3 controller.py"
3. If app_sec:
    - Insert database password: "password"
4. Lauch HTML Server:
    - **Option 1**: Using a vscode extension (Live Server), open the file "index.html" in the folder "templates" and click on "Go Live" at the bottom right corner.
    - **Option 2**: Lauch a python server in the folder "1ST-PROJECT-GROUP_13" using the command "python3 -m http.server 5500" and open the browser in the url:
        - app: "http://127.0.0.0:5500/app/templates/index.html"
        - app_sec: "http://127.0.0.0:5500/app_sec/templates/index.html
    - **Option 3**: Lauch a node server in the folder "1ST-PROJECT-GROUP_13", install using "npm install -g http-server" and run with the command "npx http-server -p 5500", open the browser in the url:
        - app: "http://127.0.0.0:5500/app/templates/index.html"
        - app_sec: "http://127.0.0.0:5500/app_sec/templates/index.html

## 6. Notes

- **Requirements**
    ```
        flask-sqlalchemy
        flask-cors
        Flask-Bcrypt
        Flask-Login
        PyJWT
        bleach
        werkzeug~=2.2.0
        markupsafe==2.1.1
        SQLAlchemy==1.4.23
        Flask==2.2.0
        jinja2~=3.0.3
    ```

- **Test Accounts**
    * **app**
        - User
            ```
            email: user@example.com
            password: pass
            ```

        - Administrator:
            ```
            email: admin@example.com
            password: password
            ```
    * **app_sec**
        - User
            ```
            email: usersec@example.com
            password: Password123!
            ```
        - Administrator:
            ```
            email: adminsec@example.com
            password: Password123!
            ```

