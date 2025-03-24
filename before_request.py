@app.before_request
def before_request():
    if request.endpoint is None:
        return render_template('404.html')
    if request.path=="/":
        return None
    for item in OUT_LIST:
        if item in request.path:
            return None
          
    result=token_control()
    if result['valid']:
        user_type=get_user_type(get_email_from_token("Bearer "+result['token']))
        if (user_type=="user" and "admin" in request.path) or (user_type=="admin" and "admin" not in request.path):
            return render_template('403.html')
        return None

    return render_template('400.html')
