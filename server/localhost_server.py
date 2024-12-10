from flask import Flask

app = Flask(__name__)
app.config['SERVER_NAME'] = 'localhost:5000'

@app.route("/")
def index():
    return "Welcome to the main domain"

@app.route("/", subdomain="test1")
def test1():
    return "This is test1.localhost"

@app.route("/", subdomain="test2")
def test2():
    return "This is test2.localhost"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
