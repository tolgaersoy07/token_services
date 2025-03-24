@app.route('/set_cookie', methods=['GET'])
def set_cookie():
    device_id = request.cookies.get('deviceID_marketapp')
    if device_id:
        response = make_response(jsonify({"message": "Cookie zaten var", "random_number": device_id}))
        return response
    random_number = secrets.token_hex(16)
    response = make_response(jsonify({"message": "Cookie set edildi", "random_number": random_number}))
    response.set_cookie(
        'deviceID_marketapp',
        random_number,  
        httponly=True,  
        secure=False, # false yap http çalışşsın
        samesite='Strict',  
        max_age=3600)
    return response
