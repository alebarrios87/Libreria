from flask import Flask, g, render_template, jsonify, url_for, flash
from flask import request, redirect, make_response
from flask import session as login_session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from functools import wraps
from database_setup import Base, Autor, Libros, Edicion, User
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import random
import string
import json
import datetime
import hashlib
import httplib2
import requests
import os

IMAGE_FOLDER = os.path.join('static', 'people_photo')

app = Flask(__name__)

app.config['image'] = IMAGE_FOLDER

CLIENT_ID = json.loads(
		open('client_secrets.json', 'r').read())['web']['client_id']

# Connect to Database and create database session
#engine = create_engine('sqlite:///blog.db?check_same_thread=false')
engine = create_engine('postgresql://iuser:user@db/libreria')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

@app.route('/login', methods=['GET', 'POST'])
def login():

	if request.method == 'GET':
		state = ''.join(random.choice(
				string.ascii_uppercase + string.digits) for x in range(32))
		# store it in session for later use
		login_session['state'] = state
		return render_template('login.html', STATE = state)
	else:
		if request.method == 'POST':
			print ("dentro de POST login")
			user = session.query(User).filter_by(
				username = request.form['email']).first()

			if user and valid_pw(request.form['email'],
								request.form['password'],
								user.pw_hash):
			
				login_session['email'] = request.form['email']
				login_session['username'] = request.form['email']
				
				return render_template('public.html', username=login_session['email'])

			else:
				error = "Usuario no registrado!!!"
				return render_template('login.html', error = error)
				
# GConnect
@app.route('/gconnect', methods=['POST'])
def gconnect():
	print ("Dentro de GConnect")
		# Validate state token
	if request.args.get('state') != login_session['state']:
		response = make_response(json.dumps('Invalid state parameter.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	# Obtain authorization code, now compatible with Python3
	code = request.data

	try:
			# Upgrade the authorization code into a credentials object
		oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
		oauth_flow.redirect_uri = 'postmessage'
		credentials = oauth_flow.step2_exchange(code)
	except FlowExchangeError:
		response = make_response(
					json.dumps('Failed to upgrade the authorization code.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response

	# Check that the access token is valid.
	access_token = credentials.access_token
	url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
				 % access_token)
	# Submit request, parse response - Python3 compatible
	h = httplib2.Http()
	result = json.loads(h.request(url, 'GET')[1])

	# If there was an error in the access token info, abort.
	if result.get('error') is not None:
			response = make_response(json.dumps(result.get('error')), 500)
			response.headers['Content-Type'] = 'application/json'
			return response

	# Verify that the access token is used for the intended user.
	gplus_id = credentials.id_token['sub']
	if result['user_id'] != gplus_id:
			response = make_response(
					json.dumps("Token's user ID doesn't match given user ID."), 401)
			response.headers['Content-Type'] = 'application/json'
			return response

	# Verify that the access token is valid for this app.
	if result['issued_to'] != CLIENT_ID:
			response = make_response(
					json.dumps("Token's client ID does not match app's."), 401)
			print ("Token's client ID does not match app's.")
			response.headers['Content-Type'] = 'application/json'
			return response

	stored_credentials = login_session.get('credentials')
	stored_gplus_id = login_session.get('gplus_id')
	if stored_credentials is not None and gplus_id == stored_gplus_id:
			response = make_response(json.dumps('Current user is already connected.'),
																	 200)
			response.headers['Content-Type'] = 'application/json'
			return response

	# Store the access token in the session for later use.
	login_session['access_token'] = credentials.access_token
	login_session['gplus_id'] = gplus_id

	# Get user info
	userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
	params = {'access_token': access_token, 'alt': 'json'}
	answer = requests.get(userinfo_url, params=params)

	data = answer.json()

	login_session['username'] = data['name']
	login_session['picture'] = data['picture']
	login_session['email'] = data['email']
	#print login_session['email']


	# user_id = getUserID(login_session['email'])
	# if not user_id:
	# 		user_id = createUser(login_session)

	# login_session['user_id'] = user_id

	output = ''
	output += '<h3>Welcome, '
	output += login_session['username']
	output += '!</h3>'
	output += '<img src="'
	output += login_session['picture']
	output += ' " style = "width: 100px; height: 100px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
	flash("you are now logged in as %s" % login_session['username'])
	print ("done!")
	print ("Usuario " + login_session['username'])
	return output
	

@app.route('/gdisconnect')
def gdisconnect():
				# Only disconnect a connected user.
		access_token = login_session.get('access_token')
		if access_token is None:
				response = make_response(
						json.dumps('Current user not connected.'), 401)
				response.headers['Content-Type'] = 'application/json'
				return response
		url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
		h = httplib2.Http()
		result = h.request(url, 'GET')[0]
		if result['status'] == '200':
				# Reset the user's sesson.
				del login_session['access_token']
				del login_session['gplus_id']
				del login_session['username']
				del login_session['email']
				del login_session['picture']
				response = make_response(json.dumps('Successfully disconnected.'), 200)
				response.headers['Content-Type'] = 'application/json'
				return redirect(url_for('showGenres'))
		else:
				# For whatever reason, the given token was invalid.
				response = make_response(
						json.dumps('Failed to revoke token for given user.', 400))
				response.headers['Content-Type'] = 'application/json'
		return response


def login_required(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		if 'username' not in login_session:
			return redirect(url_for('login'))
		return f(*args, **kwargs)
	return decorated_function

def make_salt():
	return ''.join(random.choice(
				string.ascii_uppercase + string.digits) for x in range(32))
		
def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256((name + pw + salt).encode('utf-8')).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

@app.route('/logout')
def logout():
		
		del login_session['username']

		return render_template('public.html')

# Crear usuario
@app.route('/registrar', methods=['GET', 'POST'])
def registrar():

	if request.method == 'GET':
		return render_template('add-user.html')
	else:
		if request.method == 'POST':
			username = request.form['username']
			password=request.form['password']
			email = request.form['email']

			pw_hash = make_pw_hash(username, password)
			nuevoUsuario = User(
					username = username,
					email = email,
					pw_hash=pw_hash) 
			session.add(nuevoUsuario)
			session.commit()
			login_session['username'] = request.form['username']
			return redirect(url_for('showMain'))

# Delete autor
@app.route('/Autor/eliminar/<int:IdAutor>', methods=['GET', 'POST'])
def eliminarAutor(IdAutor):

	post = session.query(Autor).filter_by(IdAutor = IdAutor).one()

	if request.method == 'GET':
		username = login_session['username']
		return render_template('delete-autor.html', post = post,username=username)
	else:
		if request.method == 'POST':
			session.delete(post)
			session.commit()
			return redirect(url_for('showAutor'))
					 

# Delete Libro
@app.route('/Libros/eliminar/<int:IdLibro>', methods=['GET', 'POST'])
def eliminarLibro(IdLibro):

	post = session.query(Libros).filter_by(IdLibro = IdLibro).one()

	if request.method == 'GET':
		username = login_session['username']
		return render_template('delete-libro.html', post = post,username=username)
	else:
		if request.method == 'POST':
			session.delete(post)
			session.commit()
			return redirect(url_for('showLibros'))
	
# Crear Autor
@app.route('/agregarAutor', methods=['GET', 'POST'])
def agregarAutor():

	if request.method == 'GET':
		username = login_session['username']
		return render_template('add-autor.html',username=username)
	else:
		if request.method == 'POST':
			print(login_session['email'])
			post = Autor(
					Nobreyapellido = request.form['Nobreyapellido'],
					Biografia=request.form['Biografia'],
					Fecha_nacimiento= request.form['Fecha_nacimiento'],
					UserID=login_session['email'])
			session.add(post)
			session.commit()
			return redirect(url_for('showAutor'))

# Crear Libro
@app.route('/agregarLibro', methods=['GET', 'POST'])
def agregarLibro():

	if request.method == 'GET':
		username = login_session['username']
		return render_template('add-libros.html',username=username)
	else:
		if request.method == 'POST':
			post = Libros(
					NombreLibro = request.form['NombreLibro'],
					Epigrafe=request.form['Epigrafe'],
					Fecha_creacion= request.form['Fecha_creacion'],
					UserID=login_session['email'])
			session.add(post)
			session.commit()
			return redirect(url_for('showLibros'))
# Crear Edicion
@app.route('/agregarEdicion', methods=['GET', 'POST'])
def agregarEdicion():
	autor = session.query(Autor).all()
	libros = session.query(Libros).all()
	if request.method == 'GET':
		username = login_session['username']
		return render_template('add-edicion.html',username=username, autor=autor,libros=libros)
	else:
		if request.method == 'POST':
			post = Edicion(
					IdLibro=request.form['IdLibro'],
					IdAutor= request.form['IdAutor'],
					Fecha_Edicion = request.form['Fecha_Edicion'],
					Cantidad = request.form['Cantidad'],
					UserID=login_session['email'])
			session.add(post)
			session.commit()
			return redirect(url_for('showEdicion'))

# Show main
@app.route('/', methods=['GET'])
@app.route('/public/', methods=['GET'])
def showMain():
	posts = session.query(Autor).all()

	if 'email' in login_session:
		username = login_session['username']
		return render_template('public.html', posts = posts, username=username)
	else:	
		return render_template('public.html', posts = posts)

# Show Autor
@app.route('/', methods=['GET'])
@app.route('/autor/', methods=['GET'])
def showAutor():
	posts = session.query(Autor).all()
	
	if 'email' in login_session:
		username = login_session['username']
		return render_template('autor.html', posts = posts, username=username)	
	else:
		return render_template('autor.html', posts = posts)

# Show Libros
@app.route('/', methods=['GET'])
@app.route('/libros/', methods=['GET'])
def showLibros():
	posts = session.query(Libros).all()
	
	if 'email' in login_session:
		username = login_session['username']
		return render_template('libros.html', posts = posts, username=username)	
	else:
		return render_template('libros.html', posts = posts)

# Show Edicion
@app.route('/', methods=['GET'])
@app.route('/edicion/', methods=['GET'])
def showEdicion():
	posts = session.query(Edicion.IdEdicion, Libros.NombreLibro,Autor.Nobreyapellido,Edicion.Fecha_Edicion,Edicion.Cantidad,Edicion.UserID).\
		join(Autor, Edicion.IdAutor==Autor.IdAutor).\
			join(Libros, Edicion.IdLibro==Libros.IdLibro)
	if 'email' in login_session:
		username = login_session['username']
		return render_template('edicion.html',posts = posts, username=username)	
	else:
		return render_template('edicion.html',posts = posts)

# Editar Autor
@app.route('/Autor/editar/<int:IdAutor>', methods=['GET', 'POST'])
def editarAutor(IdAutor):
	post = session.query(Autor).filter_by(IdAutor = IdAutor).one()

	if request.method == 'GET':
		username = login_session['username']
		return render_template('edit-autor.html', post = post,IdAutor = IdAutor, username=username)
	else:
		if request.method == 'POST':
			print(IdAutor)
			post = session.query(Autor).filter_by(IdAutor = IdAutor).one()
			post.Nobreyapellido = request.form['Nobreyapellido'],
			post.Biografia=request.form['Biografia'],
			post.Fecha_nacimiento= request.form['Fecha_nacimiento'],
			post.UserID=login_session['email'],
			session.commit()
			return redirect(url_for('showAutor'))

# Editar Libros
@app.route('/Libros/editar/<int:IdLibro>', methods=['GET', 'POST'])
def editarLibros(IdLibro):
	post = session.query(Libros).filter_by(IdLibro = IdLibro).one()

	if request.method == 'GET':
		username = login_session['username']
		return render_template('edit-libros.html', post = post,IdLibro = IdLibro, username=username)
	else:
		if request.method == 'POST':
			print(IdLibro)
			post = session.query(Libros).filter_by(IdLibro = IdLibro).one()
			post.NombreLibro = request.form['NombreLibro'],
			post.Epigrafe=request.form['Epigrafe'],
			post.Fecha_creacion= request.form['Fecha_creacion'],
			post.UserID=login_session['email']
			session.commit()
			return redirect(url_for('showLibros'))



if __name__ == '__main__':
	app.secret_key = "secret key"
	app.debug = False
	app.run(host = '0.0.0.0', port = 8080)
