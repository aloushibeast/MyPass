MyPass is a secure, pattern-driven password management web application built using Flask, SQLite, and AES-256 encryption. The system 
is designed to safely store, manage, and organize users’ sensitive information, including login credentials, credit cards, identity 
numbers, and secure notes. It incorporates multiple design patterns, Singleton, Observer, Mediator, Builder, Proxy, and 
Chain of Responsibility, to create a modular, maintainable, and extensible architecture that enhances both security and user experience.

The application allows users to create an account using an email, password, and three custom security questions. User passwords and 
security answers are hashed before storage, and all sensitive vault data is encrypted using AES-256 GCM. Once authenticated, users 
gain access to a personal vault where they can create, edit, delete, and view various types of secure items. Each item type is displayed 
with masked values by default, and users may reveal or copy sensitive information when needed. To protect privacy, MyPass automatically 
clears sensitive clipboard data after a short period and automatically logs users out after inactivity.

To help users create strong passwords, MyPass includes a password generator implemented through the Builder pattern, allowing flexible 
control over password length and complexity. A built-in strength meter visually evaluates password quality in real time. Additionally, 
the Observer pattern provides automated warnings about weak passwords or expired credit cards. Sensitive fields are protected using the 
Proxy pattern to toggle between masked and unmasked display modes without exposing raw data unnecessarily.

Session handling is centrally controlled by a Singleton-based SessionManager to ensure consistent authentication state across all routes. 
The UIMediator coordinates interactions between session management, encryption utilities, observers, and UI components to keep the 
application loosely coupled and easy to maintain. For password recovery, the Chain of Responsibility pattern validates each security 
question in sequence, ensuring a secure and structured reset process.

MyPass includes a clean and user-friendly interface built with Bootstrap and custom CSS. The web app is lightweight, easy to run locally, 
and requires no external dependencies beyond Python libraries. It is designed for educational and personal use, demonstrating secure 
software engineering practices, encryption handling, and advanced software design patterns in a practical Flask application.