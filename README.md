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

- **app_org** - Secure app 1st project
    * **backend** - backend script (controller.py)
    * **templates** - frontend scripts (.html)
    * **css** - stylesheet scripts (.css)
    * **scss** - stylesheet scripts (.scss)
    * **js** - javascript scripts (.js)
    * **images** - images (.png, .jpg, .svg, .gif)

- **app_sec** - Secure app 2nd project
    * **backend** - backend script (controller.py)
    * **templates** - frontend scripts (.html)
    * **css** - stylesheet scripts (.css)
    * **scss** - stylesheet scripts (.scss)
    * **js** - javascript scripts (.js)
    * **images** - images (.png, .jpg, .svg, .gif)

- **analysis** - All documentation to support the project
    * **prints** - directory with all the prints taken for this project
    * **report** - directory with the report in .pdf  
        * [Report_1st_project.pdf](/analyses/report/Report_1st_project.pdf)
        * [Report_2nd_project.pdf](/analyses/report/Report_2nd_project.pdf)
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
    * **ASVS** - directory with the ASVS excel list
        * [ASVS-Proj2.xlsx](/analyses/ASVS/ASVS-Proj2.xlsx)
        * **images** - directory with the images used in the report
            * **#2.1.12** - directory for #2.1.12
            * **#2.1.6** - directory for #2.1.6
            * **#2.1.8** - directory for #2.1.8
            * **#2.2.1** - directory for #2.2.1
            * **#2.2.3** - directory for #2.2.3
            * **#3.7.1** - directory for #3.7.1

- **README.md** - Guideline document for the project

## 3. Description

- **Introduction:**
    - This project involves the creation of an online shop for DETI. The main aspect was that the project should be developed in two distinct views. The 2nd project involves the evolution of DETI memorabilia online shop to comply with level 1 Application Security Verification Standard requirements. There are 3 distinct views of the project:
        * **app:** Functional online shop with vulnerabilities, icluding CWE-79 (Cross-Site Scripting) and CWE-89 (SQL Injection).
         * **app_org:** Functional and secure online shop acording to the first project.
        * **app_sec:** Functional and secure online shop acording to level 1 Application Security Verification Standard requirements.
        
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

## 5. ASVS List

List of ASVS items that we use have in our project:

-  2.1.1 
-  2.1.2
-  2.1.6
-  2.1.8
-  2.1.9
-  2.1.12
-  2.2.1
-  2.2.2
-  2.2.3
-  2.5.4
-  2.7.2
-  2.7.3
-  2.8.1
-  3.7.1
-  7.1.1
-  7.1.2
-  14.2.2


## 6. How to run

1. pip install -r requirements
2. Run the backend Server:
    - app: Directory: /app/backend "python3 controller.py"
    - app_org: Directory: /app_org/backend "python3 controller.py"
    - app_sec: Directory: /app_sec/backend "python3 controller.py"
3. If app_org or app_sec:
    - Insert database password: "password"
4. Lauch HTML Server:
    - **Option 1**: Using a vscode extension (Live Server), open the file "index.html" in the folder "templates" and click on "Go Live" at the bottom right corner.
    - **Option 2**: Lauch a python server, using the command "python3 -m http.server 5500" and open the browser in the url:
        - app: "http://127.0.0.0:5500/app/templates/index.html"
        - app_org: "http://127.0.0.0:5500/app_org/templates/index.html"
        - app_sec: "http://127.0.0.0:5500/app_sec/templates/index.html
    - **Option 3**: Lauch a node server, install using "npm install -g http-server" and run with the command "npx http-server -p 5500", open the browser in the url:
        - app: "http://127.0.0.0:5500/app/templates/index.html"
        - app_org: "http://127.0.0.0:5500/app_org/templates/index.html"
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
        pyotp
        flask-mail
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
    * **app_org**
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
    * **app_sec**
        - User
            ```
            email: zepedro@email.com
            password: 123456789pass
            ```
        - Administrator:
            ```
            email: joaopaulo@detistore.com
            password: 123456789pass
            ```
- ** Grades **
      - 1st project: ** 17.1 **
      - 2nd project: ** 18.7 **
