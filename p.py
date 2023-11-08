
from flask_n_cors import Flask, request
import flask
app = Flask('emcdr')
emcdr = ''
@app.route('/', methods =['GET'])
def i_forgot_this_functions_name():
  with open('routeslashfile.html','r') as f:return f.read()


@app.route('/i', methods=['GET'])
def handle_request():
  global emcdr 
  emcdr = request.args.get('i')
  with open('lastcolorpicked','w') as f:f.write(emcdr)
  return '200'
@app.route('/last', methods=['GET'])
def get_last():
  with open('lastcolorpicked','r') as f:return f.read()

if __name__ == '__main__':app.run(debug=False,host='127.0.0.1',port=8080,cors_enabled=False)