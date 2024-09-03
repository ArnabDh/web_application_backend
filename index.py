import json
import os
import urllib
from datetime import datetime, timedelta

from bson import json_util
from flask import Flask, request, jsonify, url_for, redirect
from flask_apscheduler import APScheduler
from flask_cors import CORS
from flask_dance.contrib.google import make_google_blueprint, google
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import firebase_admin
from firebase_admin import credentials, storage
from google.cloud import storage
import os

app = Flask(__name__)
CORS(app, origins="*", supports_credentials=True)

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app.secret_key = os.urandom(12)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
jwt = JWTManager(app)
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

client = MongoClient(os.getenv('MONGODB_URL'))
db = client['AI_Chef_Master']  # AI_Chef_Master


# google login
app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.getenv('GOOGLE_OAUTH_CLIENT_ID')
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.getenv('GOOGLE_OAUTH_CLIENT_SECRET')

google_blueprint = make_google_blueprint(
    client_id=os.getenv('GOOGLE_OAUTH_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_OAUTH_CLIENT_SECRET'),
    scope=["https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile",
           "openid"]
)
app.register_blueprint(google_blueprint, url_prefix="/login")

# #firebase credential




# cred = credentials.Certificate("credentials.json")
# firebase_admin.initialize_app(cred)

# #os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "credentials.json"
# storage_client = storage.Client()
# bucket_name = "gs://ai-chef-master-37900.appspot.com"
# bucket = storage_client.bucket(bucket_name)


@app.route("/")
def index():
    try:
        if not google.authorized:
            return redirect(url_for("google.login"))
        return redirect(url_for("google_callback"))

    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 400


@app.route("/callback")
def google_callback():
    try:
        if not google.authorized:
            return jsonify({"error": "Failed to log in."}), 400
        resp = google.get("/oauth2/v1/userinfo")
        assert resp.ok, resp.text

        user_info = resp.json()
        exist_user = db.User.find_one({'email': user_info['email']}, {'first_name': 1, 'user_id': 1})

        if not exist_user:
            user_id = "User" + user_info['given_name'].upper() + "-" + str(
                round((datetime.now().timestamp()) * 1000000))
            db.User.insert_one({
                'first_name': user_info['given_name'],
                'last_name': user_info['family_name'],
                'email': user_info['email'],
                'user_id': user_id
            })
        else:
            user_id = exist_user['user_id']

        user_info['user_id'] = user_id
        token = create_access_token(identity=user_info['email'])
        user_info['access_token'] = token
        user_info_str = urllib.parse.quote(json.dumps(user_info))

        return redirect(f"{os.getenv('FRONTEND_URL')}/login?data={user_info_str}", code=302)

    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 400


# Manual Authentication
@app.route('/auth/signup', methods=['POST'])
def register():
    try:
        first_name = request.json.get('first_name')
        last_name = request.json.get('last_name')
        country_code = request.json.get('country_code')
        phone = request.json.get('phone')
        email = request.json.get('email')
        password = request.json.get('password')

        if not (first_name and last_name and country_code and phone and email and password):
            return jsonify({'message': 'Missing required fields'}), 400
        if db.User.find_one({'email': email}):
            return jsonify({'message': 'User already exists'}), 400

        hashed_password = generate_password_hash(password)
        user_id = "User" + first_name.upper() + "-" + str(round((datetime.now().timestamp()) * 1000000))
        db.User.insert_one({
            'first_name': first_name,
            'last_name': last_name,
            'country_code': country_code,
            'phone': phone,
            'email': email,
            'password': hashed_password,
            'user_id': user_id
        })

        return jsonify({'message': 'User registered successfully'}), 201

    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 400


@app.route('/auth/login', methods=['POST'])
def loginAuth():
    try:
        email = request.json['email']
        password = request.json['password']

        user = db.User.find_one({'email': email})
        if not user or not check_password_hash(user['password'], password):
            return jsonify({'message': 'Invalid credentials'}), 401
        else:
            token = create_access_token(identity=email)
        name = user['first_name'] + " " + user['last_name']
        user_id = user['user_id']
        return jsonify(message='Login Successful', access_token=token, email=email, name=name, user_id=user_id)

    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 400


@app.route('/auth/validate-token', methods=['GET'])
@jwt_required()
def validate_token():
    try:
        current_user = get_jwt_identity()
        user = db.User.find_one({'email': current_user})
        if user:
            name = user['first_name'] + " " + user['last_name']
            user_id = user['user_id']
            return jsonify(message='Token is valid', email=current_user, name=name, user_id=user_id)
        else:
            return jsonify({'message': 'Invalid token'}), 401

    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 400


@app.route('/auth/forgetPassword', methods=['POST'])
def forgetP():
    try:
        email = request.json.get('email')
        newPassword = request.json.get('newPassword')

        db.User.update_one({"email": email}, {"$set": {"password": generate_password_hash(newPassword)}})
        return jsonify({'message': "password updates succesfully"})

    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 400


# To Generate New Dish
@app.route('/Homepage', methods=['POST'])
@jwt_required()
def generate_dish():
    try:
        data = request.get_json()
        name = data.get('name')
        quantity = data.get('quantity')
        unit = data.get('unit')
        equipments = data.get('equipments')

        if not name or not quantity or not unit or not equipments:
            return jsonify({'message': 'All fields are required'}), 400

        item = {
            "created_at": datetime.utcnow(),
            "name": name,
            "quantity": quantity,
            "unit": unit,
            "equipments": equipments
        }

        result = db.generate_dish.insert_one(item)
        if result.inserted_id:
            return jsonify({'message': 'Item created successfully', 'id': str(result.inserted_id)}), 201
        else:
            return jsonify({'message': 'Failed to create item'}), 500

    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 400


# To Show Dish into History 
@app.route("/history/<name>", methods=['GET'])
@jwt_required()
def history(name):
    try:
        item = db.generate_dish.find_one({"name": name}, {"_id": 0})
        item['created_at'] = item['created_at'].strftime('%Y-%m-%d %H:%M:%S') if 'created_at' in item else 'N/A'
        if item:
            return jsonify(item), 200
        else:
            return jsonify({'message': 'Item not found'}), 404

    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 500


#  ========================================================================================================================================


# Raj Code :
from flask import Flask, request, jsonify
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import pandas as pd
import numpy as np

# Modified data structure
data = {
    'dish_name': ['Pasta Carbonara', 'Chicken Curry', 'Caesar Salad', 'Beef Stir Fry'],
    'ingredients': [
        '400g spaghetti, 150g pancetta, 4 eggs, 50g Pecorino Romano, 50g Parmesan',
        '500g chicken breast, 2 tbsp yogurt, 1 tsp turmeric, 1 tsp garam masala, 1 onion, 3 garlic cloves, 1 tbsp ginger, 2 tbsp curry powder, 400ml coconut milk, 200ml chicken stock',
        '2 heads romaine lettuce, 1 egg yolk, 2 garlic cloves, 2 tsp Dijon mustard, 2 tsp Worcestershire sauce, 1 lemon, 1/2 tsp anchovy paste, 1/2 cup olive oil, 1 cup croutons, 1/2 cup Parmesan, 2 chicken breasts',
        '500g beef sirloin, 2 tbsp soy sauce, 1 tbsp oyster sauce, 1 tsp sesame oil, 2 tbsp vegetable oil, 2 garlic cloves, 1 tbsp ginger, 1 bell pepper, 1 onion, 1 cup broccoli, 1 cup snap peas, 1/4 cup chicken stock, 1 tbsp cornstarch'
    ],
    'steps': [
        ['Cook spaghetti in salted water', 'Fry pancetta until crispy', 'Whisk eggs and cheese',
         'Toss hot pasta with pancetta', 'Add egg mixture to create sauce', 'Serve with extra cheese and pepper'],
        ['Marinate chicken', 'Fry onion, garlic, and ginger', 'Add curry powder and chicken',
         'Pour in coconut milk and stock', 'Simmer until cooked', 'Serve with rice and naan'],
        ['Make dressing', 'Prepare lettuce and croutons', 'Grill and slice chicken', 'Toss salad with dressing',
         'Add chicken and extra cheese'],
        ['Marinate beef', 'Stir-fry garlic and ginger', 'Cook beef', 'Stir-fry vegetables',
         'Combine beef and vegetables', 'Thicken sauce', 'Serve over rice']
    ],
    'video_link': [
        'https://www.youtube.com/watch?v=GDUbWNJLPnc',
        'https://www.youtube.com/watch?v=GDUbWNJLPnc',
        'https://www.youtube.com/watch?v=GDUbWNJLPnc',
        'https://www.youtube.com/watch?v=GDUbWNJLPnc'
    ]
}

#C:/Users/ZEN/Desktop/Web-Dish/frontend/src/components/SecondaryIntelligence/data/videos/dough.mp4

df = pd.DataFrame(data)


class RecipeModel:
    def __init__(self):
        self.vectorizer = TfidfVectorizer()
        self.tfidf_matrix = None
        self.is_trained = False

    def train(self, dish_names):
        self.tfidf_matrix = self.vectorizer.fit_transform(dish_names)
        self.is_trained = True

    def find_closest_recipe(self, query):
        if not self.is_trained:
            return None
        query_vec = self.vectorizer.transform([query])
        similarities = cosine_similarity(query_vec, self.tfidf_matrix).flatten()
        closest_index = np.argmax(similarities)
        return closest_index


recipe_model = RecipeModel()
recipe_model.train(df['dish_name'])

#CHAT-GPT ROUTE
@app.route('/generate_recipe', methods=['POST'])
def generate_recipe():
    try:
        data = request.json
        dish_name = data.get('dish')
        if not dish_name:
            return jsonify({'error': 'No dish name provided'}), 400

        closest_index = recipe_model.find_closest_recipe(dish_name)
        if closest_index is None:
            return jsonify({'error': 'Model not trained'}), 500

        recipe = {
            'dish_name': df.loc[closest_index, 'dish_name'],
            'ingredients': df.loc[closest_index, 'ingredients'],
            'steps': df.loc[closest_index, 'steps'],
            'video_link': df.loc[closest_index, 'video_link']
        }
        return jsonify(recipe)
    except Exception as e:
        app.logger.error(f"Error generating recipe: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


# sidebar history
@app.route('/api/dish_history', methods=['GET', 'POST'])
def get_dish_history():
    try:
        # Test database connection
        if db.command('ping'):
            print("Pinged your deployment. You successfully connected to MongoDB!")
        else:
            return jsonify({"error": "Failed to connect to MongoDB"}), 500

        dishes_cursor = dishes.find().sort("date", -1).limit(5)
        dishes_list = json.loads(json_util.dumps(dishes_cursor))

        if not dishes_list:
            print("No dishes found in the database")
            return jsonify({"dishes": []}), 200

        for dish in dishes_list:
            if 'date' in dish and '$date' in dish['date']:
                dish['date'] = dish['date']['$date'][:10]
            else:
                dish['date'] = 'Unknown'

        return jsonify({"dishes": dishes_list})
    except Exception as e:
        app.logger.error(f"An error occurred: {str(e)}")
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


# genrated recipes
@app.route('/start-process', methods=['POST'])
def start_process():
    try:
        data = request.json
        print(data)
        return jsonify({"message": "Process started successfully"}), 200

    except Exception as e:
        print(f"Error starting process: {str(e)}")
        return jsonify({"error": "Something went wrong"}), 500
    
    
#arnab code
@app.route('/dishes', methods=['GET'])
def get_dishes():
    dishes = db.Dish.find({}, {'_id': 0})
    return jsonify([dish for dish in dishes])


@app.route('/name/<id>', methods=['GET'])
def get_details(id):
    details = db.Dish.find_one({'id': id}, {'_id': 0, 'dish_name': 1})
    return jsonify(details)


@app.route('/dishes/<id>/ingredients', methods=['GET'])
def get_ingredients(id):
    dish = db.Dish.find_one({'id': id})
    if dish:
        id = dish.get('id')
        cuisine = dish.get('Cuisine')
        name = dish.get('dish_name')
        image = dish.get('image')
        description = dish.get('description')
        type = dish.get('veg_non_veg')
        time = dish.get('cooking_time')
        ingredients = dish.get('ingredients', [])  # Replace 'ingredients' with your actual field name
        equipments = dish.get('kitchen_equipments', [])
        return jsonify({
            "ingredients": ingredients,
            "equipments": equipments,
            "Cuisine": cuisine,
            "name": name,
            "image": image,
            "description": description,
            "type": type,
            "time": time,
            "id": id
        })
    else:
        return jsonify({"error": "Dish not found"}), 404


@app.route('/recipes/<id>', methods=['GET'])
def get_recipe(id):
    dish = db.receipe.find_one({'id': id})
    if dish:
        return jsonify(dish['recipeSteps'])
    else:
        return jsonify({"error": "Recipe not found"}), 404


@app.route('/dishes/state', methods=['POST'])
def get_states():
    data = request.json
    print(data)
    state = data.get('state')
    print(state)
    cursor = db['Dish'].find({"popularity_state": state}, {"_id": 0})
    # Convert cursor to a list of dictionaries
    dishes = list(cursor)
    print(dishes)
    return jsonify(dishes)


@app.route('/feedback', methods=['POST'])
def feedback():
    data = request.json
    db.Feedback.insert_one({
        "email": data.get('email'),
        "message": data.get('message'),
        "reaction": data.get('reaction')
    })
    return jsonify({'message': 'Message added successfully'}), 201


@app.route('/steps/<id>', methods=['GET'])
def get_steps(id):
    dish = db.receipe.find_one({'id': id})
    if dish:
        return jsonify(dish['recipeSteps'])
    else:
        return jsonify({"error": "Recipe not found"}), 404
    


# Firebase setup
# firebase_storage_bucket = 'gs://ai-chef-master-37900.appspot.com'

# # Initialize Google Cloud Storage client
# storage_client = storage.Client()
# bucket = storage_client.bucket(firebase_storage_bucket)

cred = credentials.Certificate('credentials.json')
firebase_admin.initialize_app(cred, {
    'storageBucket': 'ai-chef-master-37900.appspot.com'
})
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "credentials.json"
storage_client = storage.Client()
bucket_name = "ai-chef-master-37900.appspot.com"
bucket = storage_client.bucket(bucket_name)

@app.route('/upload', methods=['POST'])
def upload_video():
    try:
        # Get dish ID and step index from the form data
        dish_id = request.form.get('dishId')
        step_index = int(request.form.get('stepIndex'))
        print(dish_id,step_index)
        print(request.files['video'])

        # Get the uploaded file from the request
        if 'video' not in request.files:
            return jsonify({'error': 'No video file part in the request'}), 400

        file = request.files['video']

        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        if file:
            filename = secure_filename(file.filename)
            dish_name = db.receipe.find_one({'id': dish_id})['name']
            folder_path = f"{dish_name}/"

            # Upload file to Firebase Storage
            blob = bucket.blob(f"{folder_path}{filename}")
            blob.upload_from_file(file)
            blob.make_public()
            video_url = blob.public_url

            # Update the MongoDB document with the new video URL
            db.receipe.update_one(
                {'id': dish_id},
                {'$set': {f'recipeSteps.{step_index}.videoSource': video_url}}
            )

            return jsonify({'message': 'Video uploaded successfully', 'video_url': video_url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500




if __name__ == '__main__':
    app.debug = True
    app.run(debug=True,host="0.0.0.0", port="8000")
