from flask import Flask, request, jsonify, g
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import secrets
import mysql.connector
import bcrypt
import MySQLdb
import datetime
from flask_login import LoginManager, login_user, login_required, current_user, UserMixin, logout_user
from user_roles import user_roles
from user_roles import insert_users_roles, user_already_exists, get_user_id, get_users_roles_role_id, get_role
import datetime
#from db import query_db
from urllib.parse import parse_qs
import stripe

#Swagger Stuff
from flask_swagger import swagger
from flask_swagger_ui import get_swaggerui_blueprint

app = Flask(__name__)
CORS(app)

# Register the blueprints ( )
app.register_blueprint(user_roles)
#app.register_blueprint(timer)

app.secret_key = secrets.token_hex(16) 
# Generate and set the JWT secret key
#app.config['JWT_SECRET_KEY'] = secrets.token_hex(16)  
# Initialize JWTManager after setting the secret key
jwt = JWTManager(app)

# Set a value to a global variable using app.config
#app.config['GLOBAL_ROUNDNUMBER'] = 0
login_manager = LoginManager(app)

# MySQL setup
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="password",
    database="projectx"
)


def load_user(user_id):
    # Implement the logic to retrieve a user from your data store based on user_id
    # For example, retrieve the user from your database
    try:
        cursor = db.cursor()
        cursor.execute('SELECT username FROM users WHERE username=%s', (user_id,))
        user_data = cursor.fetchone()      
        db.commit()
        cursor.close()        
        user = User(user_data[0])
        return user
    except MySQLdb.Error as e:
         return jsonify({'error': handle_mysql_error(e)})
    except mysql.connector.IntegrityError as e:
        error_message = str(e)  # Extract the error message from the exception
        print(error_message)
        return jsonify({'error': error_message})
    
login_manager.user_loader(load_user)

#Define a User class that inherits from UserMixin and represents your users:
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# Define the unauthorized response handler
@jwt.unauthorized_loader
def unauthorized_response(callback):
    print('Unauthorized')
    return jsonify(message='Unauthorized'), 401

# Define the invalid token response handler
@jwt.invalid_token_loader
def invalid_token_response(callback):
    print('Invalid token')
    return jsonify(message='Invalid token'), 401

# Define the expired token response handler
@jwt.expired_token_loader
def expired_token_response(expired_token):
    print('Token has expired')
    return jsonify(message='Token has expired'), 401

@app.route('/api/registration', methods=['POST'])
def registration():

    """
    User Registration Endpoint
    ---
    tags:
      - Player Registration
    post:
      summary: Register a new user
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                userpassword:
                  type: string
                email:
                  type: string
                selectedRole:
                  type: string
      responses:
        200:
          description: Registration successful
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
        400:
          description: Registration failed or user already exists
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
      parameters:
        - in: body
          name: user_data
          required: true
          description: JSON object containing user registration data
          schema:
            type: object
            properties:
              username:
                type: string
              userpassword:
                type: string
              email:
                type: string
              selectedRole:
                type: string
    """

    print('Inside api/registration')
    registrationData = request.get_json()        
    user = registrationData['username']
    userpassword = registrationData['userpassword']   
    email = registrationData['email'] 
    role = registrationData['selectedRole'] 

    password_hash = bcrypt.hashpw(userpassword.encode('utf-8'), bcrypt.gensalt())
   
    try:

        if user_already_exists(db, user) :            
            return jsonify({'error': 'User already exists'}), 409 
        else:
            cursor = db.cursor()
            sql = "INSERT INTO users (username, password_hash, email) VALUES (%s, %s, %s)"
            val = (user, password_hash, email)
            cursor.execute(sql, val)
            db.commit()
            cursor.close()
            #Call users_roles table to update with user roles from users_roles module
            sucess = insert_users_roles(db, user, role)
            if sucess:              
                return jsonify({'message': 'Registration successful with '+sucess}), 200
            else:
                return jsonify({'error': 'Registration Failed with User and Role'}), 200   

    except MySQLdb.Error as e:
        error_code = e.errno  # Get the MySQL error code
        if error_code == 409:
            error_message = "Duplicate entry. User already exists."
        else:
            error_message = "An error occurred during registration."
        return jsonify({"error": error_message}), 400
    except mysql.connector.IntegrityError as e:
        error_code = e.errno  # Get the MySQL error code
        if error_code == 1062:
            error_message = "Duplicate entry. User already exists."
        else:
            error_message = "An error occurred during registration."

        return jsonify({"error": error_message}), 400

    
@app.errorhandler(MySQLdb.Error)
def handle_mysql_error(e):
    return jsonify({'error': 'MySQL Error: ' + str(e)})

@app.route('/api/userlogin', methods=['POST'])
def userlogin():
    """
    User Login Endpoint
    ---
    tags:
      - Player Login
    post:
      summary: Authenticate user and generate access token
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                password:
                  type: string
      responses:
        200:
          description: Login successful
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                  user:
                    type: string
                  role:
                    type: string
                  accessToken:
                    type: string
        401:
          description: Invalid credentials
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
        404:
          description: User not found
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
      parameters:
        - in: body
          name: user_credentials
          required: true
          description: JSON object containing user credentials
          schema:
            type: object
            properties:
              username:
                type: string
              password:
                type: string
    """

    data = request.get_json()       
    user = data['username']
    password = data['password']

    try:
        cursor = db.cursor()       
       # Fetch user data from the database based on the username
        cursor.execute('SELECT password_hash FROM users WHERE username = %s', (user,))
        user_data = cursor.fetchone()
        db.commit()
        cursor.close()  
        if user_data[0] is not None:
            #print(user_data)
            # Encode the user-entered password as bytes
            user_password_bytes = password.encode('utf-8')

            if user_data:
                stored_password_hash = user_data[0]
                stored_password_hash = stored_password_hash.encode('utf-8')
                #if pbkdf2_sha256.verify(password, stored_password_hash):
                if bcrypt.checkpw(user_password_bytes, stored_password_hash):                
                    user_id = User(user)  # Replace with your actual user object
                    #login_user(user_id)                    

                    #get user_id by passing user to users table
                    user_id = get_user_id(db, user)                   
                    #print(user_id)
                    #get role_id by passing user_id to users_roles table
                    role_id = get_users_roles_role_id(db, user_id)
                    #print(role_id)
                    #get role from roles table by passing role_id
                    role = get_role(db, role_id)
                    #print(role)

                    access_token = generate_token_with_expiration(user_id)
                    #return jsonify(access_token=access_token), 200
                    print("access_token : ",access_token)

                    return jsonify({
                        "message": "Login successful",
                        "user": user,
                        "role": role,
                        "accessToken":access_token,
                    }), 200                 

                else:
                    return jsonify({'error': 'Invalid credentials'}), 401
            else:
                return jsonify({'error': 'User not found'}), 404
        else:
            return jsonify({'error': 'User not found'}), 404 
                          
    except MySQLdb.Error as e:
         return jsonify({'error': handle_mysql_error(e)})
    except mysql.connector.IntegrityError as e:
        error_message = str(e)  # Extract the error message from the exception
        print(error_message)
        return jsonify({'error': error_message})

@app.route('/api/protected', methods=['GET'])
@login_required
def protected():
    return jsonify({'message': f'Hello, {current_user.id}! This is a protected route.'})

@app.route('/api/logout', methods=['GET'])
#@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out successfully"}), 200
 
#To get roles
@app.route('/api/roles', methods=['GET'])
def get_roles():
    """
    Get User Roles Endpoint
    ---
    tags:
      - Available Roles 
    get:
      summary: Retrieve user roles
      responses:
        200:
          description: User roles retrieved successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  userRoles:
                    type: array
                    items:
                      type: object
                      properties:
                        role:
                          type: string
        404:
          description: No roles found
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
        500:
          description: An error occurred while retrieving roles
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
    """
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT role FROM roles")
        roles = cursor.fetchall()
        cursor.close()

        print(roles)

        if roles:
            return jsonify({"userRoles": roles}), 200
        else:
            return jsonify({"message": "No roles found"}), 404
        
    except mysql.connector.Error as e:
        error_message = str(e)  # Extract the error message from the exception        
        if "MySQL Connection not available" in error_message:
            return jsonify({"error": "MySQL Connection not available"}), 500
        else:
            return jsonify({"error": "An error occurred"}), 500
        
#To get identitytypes
@app.route('/api/identitytypes', methods=['GET'])
# @jwt_required()
def get_identitytypes():   
    try:
        # jwt_login_user = get_jwt_identity()       
        # print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity
        
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM identityproof")
        identitytypes = cursor.fetchall()  
        cursor.close()

        if identitytypes:
            return jsonify({"identitytypes": identitytypes,
                            "message":"You are authorized!"
                            }), 200
        else:
            return jsonify({"message":'You are authorized! and No identitytypes found'}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)})  
        
#To get districts
@app.route('/api/districts', methods=['GET'])
# @jwt_required()
def get_districts():
   
    try:
        # jwt_login_user = get_jwt_identity()       
        # print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity
        
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM district")
        districts = cursor.fetchall()  
        cursor.close()

        if districts:
            return jsonify({"districts": districts,
                            "message":"You are authorized!"}), 200
        else:
            return jsonify({"message":'You are authorized! and No districts found'}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)})  

#To get States
@app.route('/api/states', methods=['GET'])
# @jwt_required()
def get_states():
   
    try:
        # jwt_login_user = get_jwt_identity()       
        # print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity
        
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM state")
        states = cursor.fetchall()  
        cursor.close()

        if states:
            return jsonify({"states": states,
                            "message":"You are authorized!"
                            }), 200
        else:
            return jsonify({"message":'You are authorized! and No states found'}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)})  


#To get Countries
@app.route('/api/countries', methods=['GET'])
#@jwt_required()
def get_countries():
   
    try:
        #jwt_login_user = get_jwt_identity()       
        #print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity
        
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM country")
        countries = cursor.fetchall()  
        cursor.close()

        if countries:
            return jsonify({"countries": countries,
                            "message":"You are authorized!"                            
                            }), 200
        else:
            return jsonify({"message":'You are authorized! and No countries found'}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)})  


# API endpoint to add a Candidate
@app.route('/api/customers', methods=['POST'])
@jwt_required()
def add_customers():
    data = request.get_json()
    #name, age, dateOfBirth, qualification, assetsValue, party, address, district, state, country
    first_name = data['firstName']
    last_name = data['lastName']
    phone_number = data['phoneNumber']
    email = data['emailId']
    booking_date = data['bookingDate']
    project_name = data['projectName']
    identity_type = data['identityType']
    identity_value = data['identityNumber']
    address = data['address']
    district = data['district']
    state = data['state']
    country = data['country']   

    jwt_login_user = get_jwt_identity() 
    print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity

    cursor = db.cursor()
    sql = "INSERT INTO customers (first_name, last_name, phone_number, email, booking_date, project_name, identity_type, identity_value, address, district, state, country) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    val = (first_name, last_name, phone_number, email, booking_date, project_name, identity_type, identity_value, address, district, state, country)
    cursor.execute(sql, val)
    db.commit()
    cursor.close()

    return jsonify({
                    "message": "Customer record inserted successfully", 
                    "user":jwt_login_user,
                    }), 200

# API to get details of district by taking district name
@app.route('/api/customers', methods=['GET'])
@jwt_required()
def get_customers():
  try:
      jwt_login_user = get_jwt_identity() 
      print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity

     
      district = request.args.get('selectedDistrict')
      month = request.args.get('selectedMonth')
      year = request.args.get('selectedYear')

      #print("customers  district:", district, "month :", month, "year :",year)

      cursor = db.cursor()
      # Use parameterized query to prevent SQL injection
      sql_query = "SELECT concat(first_name,' ',last_name) as customer_name, project_name, booking_date FROM customers WHERE district = %s AND month = %s AND YEAR = %s"

      cursor = db.cursor(dictionary=True)     
      cursor.execute(sql_query, (district, month, year)) 
      customers = cursor.fetchall()
    

      db.commit()
      cursor.close()

      return jsonify({
          "customers": customers,
          "message": " customers retrieved successfully..!",          
          "user":jwt_login_user,
      }), 200
  
  except Exception as e:
      return jsonify({"error": str(e)}), 500
  
#To get assettypes
@app.route('/api/assettypes', methods=['GET'])
def get_assettypes():   
    try:
               
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT asset_type FROM asset_type")
        assettypes = cursor.fetchall()  
        cursor.close()

        #print("Asset Types :", jsonify(assettypes))
        if assettypes:
            return jsonify({"assettypes": assettypes,
                            "message":"You are authorized!"
                            }), 200
        else:
            return jsonify({"message":'You are authorized! and No assettypes found'}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)})  
    
# API to get details of assets by taking asset_type 
@app.route('/api/assets', methods=['GET'])
@jwt_required()
def get_assets():
  try:
      jwt_login_user = get_jwt_identity() 
      print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity

      asset_type = request.args.get('selectedAssetType')

      if asset_type == 'ALL':
          sql_query = "SELECT CONCAT(first_name, ' ', last_name) AS customer_name, project_name, booking_date, asset_name, asset_value, asset_location FROM asset"
          cursor = db.cursor(dictionary=True)
          cursor.execute(sql_query)
          assets = cursor.fetchall()
      else:
          # Use parameterized query to prevent SQL injection
          sql_query = "SELECT CONCAT(first_name, ' ', last_name) AS customer_name, project_name, booking_date, asset_name, asset_value, asset_location FROM asset WHERE asset_type = %s"
          cursor = db.cursor(dictionary=True)
          cursor.execute(sql_query, (asset_type,))
          assets = cursor.fetchall()
    
      #print("Assets :", assets)

      db.commit()      
      cursor.close()

      return jsonify({
          "assets": assets,
          "message": " assets retrieved successfully..!",          
          "user":jwt_login_user,
      }), 200
  
  except Exception as e:
      return jsonify({"error": str(e)}), 500

#To get paymenttypes
@app.route('/api/paymenttypes', methods=['GET'])
def get_paymenttypes():   
    try:
               
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT payment_type FROM payment_type")
        paymenttypes = cursor.fetchall()  
        cursor.close()

        #print("Asset Types :", jsonify(paymenttypes))
        if paymenttypes:
            return jsonify({"paymenttypes": paymenttypes,
                            "message":"You are authorized!"
                            }), 200
        else:
            return jsonify({"message":'You are authorized! and No paymenttypes found'}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)})  
    

# API to get details of payments by taking payment_type 
@app.route('/api/payments', methods=['GET'])
@jwt_required()
def get_payments():
  try:
      jwt_login_user = get_jwt_identity() 
      print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity

      payment_type = request.args.get('selectedPaymentType')

      if payment_type == 'ALL':
          sql_query = "SELECT CONCAT(first_name, ' ', last_name) AS customer_name, project_name, asset_location, payment_type, down_payment_amount, phase FROM payment"
          cursor = db.cursor(dictionary=True)
          cursor.execute(sql_query)
          payments = cursor.fetchall()
      else:
          # Use parameterized query to prevent SQL injection
          sql_query = "SELECT CONCAT(first_name, ' ', last_name) AS customer_name, project_name, asset_location, payment_type, down_payment_amount, phase FROM payment WHERE payment_type = %s"
          cursor = db.cursor(dictionary=True)
          cursor.execute(sql_query, (payment_type,))
          payments = cursor.fetchall()
    
      #print("Payments :", payments)

      db.commit()      
      cursor.close()

      return jsonify({
          "payments": payments,
          "message": " payments retrieved successfully..!",          
          "user":jwt_login_user,
      }), 200
  
  except Exception as e:
      return jsonify({"error": str(e)}), 500

# API to get details of payments by taking project_name and first_name, last_name 
@app.route('/api/paymentreceipts', methods=['GET'])
@jwt_required()
def get_paymentreceipt():
  try:
      jwt_login_user = get_jwt_identity() 
      print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity

      project_name = request.args.get('projectName')
      customer_name = request.args.get('customerName')
      asset_location = request.args.get('asset_location')

      sql_query = "SELECT CONCAT(first_name, ' ', last_name) AS customer_name, project_name, asset_location, payment_type, down_payment_amount, phase, plot_number FROM payment WHERE 1=1"
      conditions = []
      params = []

      if project_name is not None:
          conditions.append("project_name = %s")
          params.append(project_name)

      if customer_name is not None:
          conditions.append("customer_name = %s")
          params.append(customer_name)

      if asset_location is not None:
          conditions.append("asset_location = %s")
          params.append(asset_location)

      if conditions:
          sql_query += " AND " + " AND ".join(conditions)

      print("SQL Query :", sql_query)
      print("params :", tuple(params))

      cursor = db.cursor(dictionary=True)
      cursor.execute(sql_query, tuple(params))
      paymentreceipts = cursor.fetchall()

      db.commit()
      cursor.close()

      return jsonify({
          "paymentreceipts": paymentreceipts,
          "message": " paymentreceipts retrieved successfully..!",          
          "user":jwt_login_user,
      }), 200
  
  except Exception as e:
      return jsonify({"error": str(e)}), 500
# API to get projects
@app.route('/api/projects', methods=['GET'])
@jwt_required()
def get_projects():
  try:
     
      jwt_login_user = get_jwt_identity() 
      print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity

      cursor = db.cursor(dictionary=True)
      cursor.execute("SELECT DISTINCT project_name FROM asset")
      projects = cursor.fetchall()
    
      print("projects :", projects)

      db.commit()      
      cursor.close()

      return jsonify({
          "projects": projects,
          "message": " locations retrieved successfully..!" ,          
          "user":jwt_login_user,
      }), 200
  
  except Exception as e:
      return jsonify({"error": str(e)}), 500

# API to get asset_locations based on project_name
@app.route('/api/asset_locations', methods=['GET'])
@jwt_required()
def get_asset_locations():
  try:
     
      jwt_login_user = get_jwt_identity() 
      print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity

      project_name = request.args.get('projectName')

      # Use parameterized query to prevent SQL injection
      sql_query = "SELECT asset_location FROM asset WHERE project_name = %s"

      cursor = db.cursor(dictionary=True)
      cursor.execute(sql_query, (project_name,))
      locations = cursor.fetchall()
    
      print("locations :", locations)

      db.commit()      
      cursor.close()

      return jsonify({
          "locations": locations,
          "message": " locations retrieved successfully..!" ,          
          "user":jwt_login_user,
      }), 200
  
  except Exception as e:
      return jsonify({"error": str(e)}), 500

# API to get details of district by taking district name
@app.route('/api/customers_for_paymentreceipt', methods=['GET'])
@jwt_required()
def get_customers_for_paymentreceipt():
  try:
      jwt_login_user = get_jwt_identity() 
      print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity

     
      project_name = request.args.get('projectName')
      asset_location = request.args.get('assetLocation')
     

      #print("Payment  projectName:", project_name, "assetLocation :", asset_location)

      cursor = db.cursor()
      # Use parameterized query to prevent SQL injection
      sql_query = "SELECT DISTINCT concat(first_name,' ',last_name) as customer_name, project_name FROM payment WHERE project_name = %s AND asset_location = %s"

      cursor = db.cursor(dictionary=True)     
      cursor.execute(sql_query, (project_name, asset_location)) 
      customers = cursor.fetchall()
    

      db.commit()
      cursor.close()

      return jsonify({
          "customers": customers,
          "message": " payment receipt- customers retrieved successfully..!",          
          "user":jwt_login_user,
      }), 200
  
  except Exception as e:
      return jsonify({"error": str(e)}), 500

# API to get details of district by taking district name
@app.route('/api/districtinfo', methods=['GET'])
@jwt_required()
def get_districtinfo():
  try:
      jwt_login_user = get_jwt_identity() 
      print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity

      district = request.args.get('district')

      if district:       
         district = district.upper()  # Convert constitution_name to uppercase

      cursor = db.cursor()
      # Use parameterized query to prevent SQL injection
      sql_query = "SELECT id, name FROM district WHERE name = %s"

      cursor = db.cursor(dictionary=True)     
      cursor.execute(sql_query, (district,)) 
      districtinfo = cursor.fetchall()
      print("districtinfo :", districtinfo)

      db.commit()
      cursor.close()

      return jsonify({
          "districtinfo": districtinfo,
          "message": " Districtinfo retrieved successfully..!",          
          "user":jwt_login_user,
      }), 200
  
  except Exception as e:
      return jsonify({"error": str(e)}), 500

# To UPDATE Constitution details
@app.route('/api/updatedistrict', methods=['POST'])
@jwt_required()
def update_district():
    
    data = request.get_json()

    # Check if data is a list and not empty
    if isinstance(data, list) and data:
        # Extract the first element of the list
        constitution_info = data[0]

        id = constitution_info['id']
        name = constitution_info['name']
        

        jwt_login_user = get_jwt_identity()
        print(f"Received JWT Identity: {jwt_login_user}")

        cursor = db.cursor()
        sql = "UPDATE district SET name = %s WHERE id = %s"
        val = (name, int(id))
        cursor.execute(sql, val)
        db.commit()
        cursor.close()

        return jsonify({
            "message": "district record updated successfully",
            "user": jwt_login_user,
        })

    else:
        return jsonify({"error": "Invalid or empty data format"})

    
#To get Current Time
@app.route('/api/current-time')
def get_current_time():
    """
    Current Time Endpoint
    ---
    tags:
      - Time
    get:
      summary: Get the current time
      responses:
        200:
          description: Return the current time
          content:
            application/json:
              schema:
                type: object
                properties:
                  current_time:
                    type: string
                    format: date-time
    """
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return jsonify({"current_time": current_time})

# Example of generating a token with expiration
def generate_token_with_expiration(user_id):
    # Set the expiration time, e.g., 1 hour from now
    expiration = datetime.timedelta(hours=4)    
    # Create a JWT access token with an expiration
    access_token = create_access_token(identity=user_id, expires_delta=expiration)    
    return access_token

@app.route('/api/swagger')  # This endpoint serves your Swagger specification
def generate_swagger_spec():
    # Generate the Swagger specification (JSON or YAML) for your API
    swag = swagger(app)
    swag['info']['title'] = 'Score Recorder'
    swag['info']['version'] = '1.0'
    return jsonify(swag)

# Swagger UI configuration
SWAGGER_URL = '/api/docs'  # URL for Swagger UI
API_URL = '/api/swagger'   # URL to your Swagger JSON or YAML file

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Score Recorder"  # Specify your app name
    }
)

app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# Set your secret API key from the Stripe Dashboard
stripe.api_key = 'YOUR_STRIPE_SECRET_KEY'

# To get client secret key from Stripe Dashboard, which is third party vendor
@app.route('/api/create-payment-intent', methods=['POST'])
@jwt_required()
def create_payment_intent():
    try:
        
        jwt_login_user = get_jwt_identity() 
        print(f"Received JWT Identity: {jwt_login_user}")  # Log the JWT identity

        # Retrieve the amount and currency from the request
        amount = request.json['amount']
        currency = request.json['currency']

        # Create a PaymentIntent
        payment_intent = stripe.PaymentIntent.create(
            amount=amount,
            currency=currency
        )

        # Send the client secret back to the client (frontend)
        return jsonify({'clientSecret': payment_intent.client_secret}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    #app.run()
    app.run(host='127.0.0.1', port=5003) # Change the port as needed
    #app.run(debug=True)
