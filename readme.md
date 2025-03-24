
# 🔐 Token Services – Secure JWT Management for Flask Apps

**Token Services** is a modular and reusable authentication module designed for Flask-based web applications.  
It offers secure JWT-based access & refresh token generation, device-level session validation, token encryption, and role-based access control.

---

## 🚀 Key Features

- ✅ **Access & Refresh Token Creation**  
  Generate short-lived access tokens and long-lived refresh tokens using `PyJWT`.

- 🔒 **Encrypted Refresh Tokens**  
  Refresh tokens are encrypted with `Fernet` before saving to the database.

- 🛡️ **Device Binding**  
  Tokens are linked with a `deviceID` (stored in cookies) to prevent token theft and misuse.

- 👨‍💼 **User Role Detection**  
  Automatically determines whether the authenticated user is a **user**, **admin**, or **no_one** based on email.

- 🔁 **Auto Access Token Refreshing**  
  When the access token expires, it automatically checks the refresh token and issues a new one.

- 📵 **Endpoint-Based Access Control**  
  Integrated `before_request` logic to protect routes based on token & user type.

---

## 🧠 How It Works

### Token Generation:
- Access Token → Valid for 60 minutes  
- Refresh Token → Valid for 30 days (daily reset at 04:00 AM)

### Token Control Flow:
1. Checks if the endpoint is in `OUT_LIST` (public routes)
2. If not → Validates token:
   - Token is present?
   - Token matches device ID?
   - Token expired?
   - If expired → Can refresh token be used?
3. Access granted only if all checks pass.

---

## 🔧 Usage

```python
from token_services import create_access_token, create_refresh_token, token_control
```
### ✅ Save To deviceID
```js
fetch('/set_cookie', {
  method: 'GET',
  credentials: 'include' 
})
.then(response => response.json())
.then(data => {
  console.log("Response:", data);
})
.catch(error => {
  console.error("An error occurred:", error);
});

```

### ✅ Create Access Token
```python
access_token = create_access_token(email)
```

### 🔄 Create & Save Encrypted Refresh Token
```python
save_refresh_token_to_db(email)
```

### 🔍 Token Validation

```python
@app.route('/access_token_validate', methods=['POST'])
def access_token_validate():
    result = token_control()
    if result['valid']:
        return jsonify({
            'valid': True,
            'user_type': result['user_type'],
            'token': result['token']
        }), 200
    return jsonify({'valid': False, 'message': result['error_code']}), result['code']
```

---

## 🛠️ Dependencies
- Flask
- PyJWT
- cryptography (Fernet)
- MySQL or compatible DB
- `deviceID` cookie (sent from frontend)

---

## 🔐 Security Highlights

- `@app.before_request` integration  
- Tokens linked to device ID  
- Expired tokens are only refreshed if valid refresh token exists  
- Refresh tokens are stored **encrypted**

---

## 📁 Project Structure

```
token_services/
├── token_services.py           # Core JWT functions
├── token_encryption.py         # Fernet-based encryption logic
├── db.py                       # MySQL DB connection
├── config.py                   # Secret keys & constants
├── requirements.py             # Requirements
├── set_cookie.py               # deviceID function
├── before_request.py           # before_request API endpoint


```


## 👨‍💻 Developer: TOLGA ERSOY

🎓 Pamukkale University – Computer Engineering | Full Stack Developer  


