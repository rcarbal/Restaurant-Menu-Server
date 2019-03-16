from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask import session as login_session
from google.oauth2 import id_token
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from urllib3.connectionpool import xrange

from database_setup import Base, Restaurant, MenuItem
import random, string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

# Google API
from google.oauth2 import id_token
from google.auth.transport import requests as goo_auth_request

import httplib2
import json
from flask import make_response
import requests

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

app = Flask(__name__)

engine = create_engine('sqlite:///restaurantmenu.db', connect_args={'check_same_thread': False})
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/gconnect', methods=['POST'])
def gconnect():
    
    try:
        if (request.args.get('state') != login_session['state']):
            response = make_response(json.dumps('Invalid state parameter'), 401)
            response.heaers['Content-Type'] = 'application/json'
            return response
        token = request.form['idtoken']
        credentials = id_token.verify_oauth2_token(token, goo_auth_request.Request(), CLIENT_ID)
        if credentials['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            response = make_response(json.dumps('Failed to upgrade the authorization code'), 401)
            response.header['Content-Type'] = 'application/json'
            return response
    except ValueError:
        # Invalid Token
        pass
        # TODO: Udacity requires a id_token verification by appending it to a google endpoin it's already verified'
    url = ('https://oauth2.googleapis.com/tokeninfo?id_token=%s' % token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is used for the intended user
    g_id = credentials['sub']
    if result['aud'] != CLIENT_ID:
        response = make_response(json.dumps("Token's client ID does not match app's"), 401)
        print("Token's client ID does not match app's")
        response.headers['Content-Type'] = 'application/json'
        return response
    # Check if user is already logged into the system
    stored_credentials = login_session.get('credentials')
    stored_g_id = login_session.get('g_id')
    if stored_credentials is not None and g_id == stored_g_id:
        response = make_response(json.dumps('Current user is already connected'), 200)
        response.headers['Content-Type'] = 'application/json'
        print('User already logged in')
        return response
    login_session['credentials'] = credentials
    login_session['g_id'] = g_id

    #Get user info
    login_session['username']=result['name']
    login_session['email'] = result['email']
    login_session['picture'] = result['picture']

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print("User successfully logged in")
    return output


# Revoke the users token and reset their login_session
@app.route("/gdisconnect")
def gdisconnect():
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(json.dumps('Current user not connected'), 401)
        response.header['Content-Type'] = 'application/json'
        return response
    access_token = credentials['sub']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s'%access_token
    h = httplib2.Http()
    result  = h.request(url, 'GET')[0]

    if result['status'] == '200':
        #Reset the user's session
        del login_session['credentials']
        del login_session['g_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps("Successfully disconnected"), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason the token was invalid
        response = make_response(json.dumps("Failed to revoke token for given user"), 400)
        response.headers['Content-Type'] = 'application/json'
        print('user logged out')
        return response



# Create a state token to prevent request forgery.
# Store in the session for later validation.


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Making an API Endpoint (GET Request)
@app.route('/restaurant/<int:restaurant_id>/menu/JSON/')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id).all()
    return jsonify(MenuItem=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/<int:menu_id>/JSON/')
def menuItemJSON(restaurant_id, menu_id):
    menuItem = session.query(MenuItem).filter_by(id=menu_id).one()
    return jsonify(MenuItem=menuItem.serialize)


@app.route('/')
@app.route('/restaurants/<int:restaurant_id>/')
def restaurantMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant.id)
    return render_template('menu.html', restaurant=restaurant, items=items)


# Task 1: Create route for newMenuItem function here

@app.route('/restaurants/<int:restaurant_id>/new/', methods=['GET', 'POST'])
def newMenuItem(restaurant_id):
    if request.method == 'POST':
        newItem = MenuItem(name=request.form['name'], restaurant_id=restaurant_id)
        session.add(newItem)
        session.commit()
        flash("New menu item created")
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))
    else:
        return render_template('newmenuitem.html', restaurant_id=restaurant_id)


# Task 2: Create route for editMenuItem function here
@app.route('/restaurant/<int:restaurant_id>/<int:menu_id>/edit/', methods=['GET', 'POST'])
def editMenuItem(restaurant_id, menu_id):
    editItem = session.query(MenuItem).filter_by(id=menu_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editItem.name = request.form['name']
            session.add(editItem)
            session.commit()
            flash("Item has been edited")
            return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))
    else:
        return render_template('editmenuitem.html', restaurant_id=restaurant_id, menu_id=menu_id, item=editItem)


# Task 3: Create a route for deleteMenuItem function here

@app.route('/restaurant/<int:restaurant_id>/<int:menu_id>/delete/', methods=['GET', 'POST'])
def deleteMenuItem(restaurant_id, menu_id):
    itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash("Item has been deleted")
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))
    else:
        return render_template('deletemenuitem.html', item=itemToDelete)


if __name__ == '__main__':
    # if the server notices a code change it will restart the server
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='127.0.0.1', port=5000)
