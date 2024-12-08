# Food Donation Management and Tracking System

## Brief Overview of the Project
The **Food Donation Management and Tracking System** is a Python-based web application with a Flask-powered UI and HTML/CSS design. It is built to facilitate and manage food donations by connecting donors and recipients. The system integrates with a MySQL database for secure data storage and provides a role-based system to streamline food donation and distribution while ensuring transparency and accountability.

---

## Features

### Donor Features:
- Add food donations with detailed item information.
- Track active and past contributions.
- Delete pending donations if needed.
- Receive:
  - Notifications for status updates.
  - Alerts for donations nearing expiration.
  - Feedback from recipients.

### Recipient Features:
- View available donations and request specific ones using their IDs.
- Track active and past requests.
- Receive:
  - Notifications about updates on donation statuses.
  - Feedback for donations they receive.

### Admin Features:
- Access real-time donation statistics, including metrics on completed, pending, and canceled donations.
- Monitor user activities and review system logs for effective management.
- Delete existing users and associated logs if necessary.

---

## Project Prerequisites
Ensure the following are installed:

- **Python (Version 3.8 or higher)**: Ensure Python is installed and added to your system's PATH. [Download Python](https://www.python.org/).
- **MySQL Server (Version 8.0 or higher)**: A relational database server is required to store and manage application data. [Download MySQL Server](https://dev.mysql.com/downloads/).
- **Flask Framework**: A lightweight Python web framework used for building the application.
- **dotenv**: For securely managing environment variables.

---

## Install Required Libraries

Install the dependencies listed below:

- Flask
- Flask-MySQL-Connector
- python-dotenv

### Using pip
Manually install the libraries with the following command:
```bash
pip install flask flask-mysql-connector python-dotenv
