
# Password Manager

This is a Web-based password manager application that allows users to securely store, manage, and retrieve passwords for different services.


## Features

- User Authentication
- Password Encryption and Decryption
- Add, Update, and View Passwords
- Responsive UI with Tailwind CSS
- Secure storage using PostgreSQL

##  Setup Instructions
#### clone the Repository
```
git clone https://github.com/mzziin/password-manager.git
cd password-manager
```
#### Create a Virtual Environment
```
python -m venv env
source env/bin/activate  # On Windows use `env\Scripts\activate`
```
#### Install Dependencies
```
pip install -r requirements.txt
```
#### Environment Variables
 Create a .env file in the root directory of the project and add the following environment variables:
```
SECRET_KEY=your_secret_key
SQLALCHEMY_DATABASE_URI=postgresql://username:password@localhost:5432/pswd_mngr
```

#### Generate Encryption Key
Generate a secret key for encryption and save it to a file named secret.key
```
from cryptography.fernet import Fernet

key = Fernet.generate_key()
with open('secret.key', 'wb') as key_file:
    key_file.write(key)
```
#### Database Migration
```
flask db init
flask db migrate -m "Initial migration."
flask db upgrade
```
## Running the Application
### Start the Flask Server
```
python3 manage.py
```
## Contributing

Contributions are always welcome!
Contributions are welcome! Please create an issue or pull request with any improvements.:slightly_smiling_face:

