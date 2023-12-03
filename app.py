from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from os import environ
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, create_refresh_token, get_jwt_identity, get_jwt
)
from werkzeug.exceptions import BadRequest
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from datetime import timedelta

app = Flask(__name__)
app.app_context().push()
app.config['SQLALCHEMY_DATABASE_URI'] = environ.get('DB_URL')
db = SQLAlchemy(app)
app.config['JWT_SECRET_KEY'] = 'simkytJWTsecret!'
jwt = JWTManager(app)

class Category(db.Model):
    __tablename__ = 'categories'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(25), unique=True, nullable=False)
    description = db.Column(db.String(100), unique=True, nullable=False)

    subcategories = db.relationship('SubCategory', backref='category', lazy=True, cascade="all, delete-orphan")

    def json(self):
        return {'id': self.id,'name': self.name, 'description': self.description}

class SubCategory(db.Model):
    __tablename__ = 'subcategories'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(25), unique=True, nullable=False)
    description = db.Column(db.String(100), unique=True, nullable=False)

    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)

    foods = db.relationship('Food', backref='subcategory', lazy=True, cascade="all, delete-orphan")

    def json(self):
        return {'id': self.id,'name': self.name, 'description': self.description, 'category_id': self.category_id}


class Food(db.Model):
    __tablename__ = 'foods'

    id = db.Column(db.String(255), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    brand = db.Column(db.String(50), nullable=True)

    kcal = db.Column(db.Float, nullable=False)
    carbs = db.Column(db.Float, nullable=False)
    fat = db.Column(db.Float, nullable=False)
    protein = db.Column(db.Float, nullable=False)

    serving = db.Column(db.String(20), nullable=False)
    perserving = db.Column(db.String(5), nullable=False)
    size = db.Column(db.Float, nullable=False)

    subcategory_id = db.Column(db.Integer, db.ForeignKey('subcategories.id'), nullable=False)
    user = db.Column(db.String(255), db.ForeignKey('user.userId'), nullable=False)

    def json(self):
        return {
            'id': self.id, 'name': self.name, 'brand': self.brand,
            'kcal': self.kcal, 'carbs': self.carbs, 'fat': self.fat,
            'protein': self.protein, 'serving': self.serving,
            'perserving': self.perserving, 'size': self.size,
            'subcategory_id': self.subcategory_id
        }

class User(db.Model):
    __tablename__ = 'user'

    userId = db.Column(db.String(255), primary_key=True)
    name = db.Column(db.String(25), unique=True, nullable=False)
    passwordHash = db.Column(db.String(255))
    emailAddress = db.Column(db.String(100), unique=True, nullable=False)
    forceRelogin = db.Column(db.Boolean, nullable=False, default=False)

    roles = db.relationship('UserRole', backref='user', lazy=True)

    def set_password(self, password):
        self.passwordHash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.passwordHash, password)

    def json(self):
        return {'userId': self.userId, 'name': self.name, 'emailAddress': self.emailAddress, 'forceRelogin': self.forceRelogin}


class UserRole(db.Model):
    __tablename__ = 'userrole'

    userRoleId = db.Column(db.String(255), primary_key=True)
    name = db.Column(db.String(25), unique=False, nullable=False) # allows several rows with the same role name

    userId = db.Column(db.String(255), db.ForeignKey('user.userId'), nullable=False)

    def json(self):
        return {'userRoleId': self.userRoleId, 'name': self.name, 'user': self.user}

db.create_all()

@app.route('/test', methods=['GET'])
def test():
    return make_response(jsonify({'message': 'test route'}), 200)

# authentication
################################################################################################################################################

@app.route('/api/guest_access', methods=['POST'])
def guest_access():
    guestId = str(uuid.uuid4())
    guest_identity = {'userId': guestId, 'name': 'GuestUser'}

    issuer = 'simkyt'
    audience = 'TrustedClient'

    additional_claims = {
        'roles': ['guest'],
        'iss': issuer,
        'aud': audience,
    }

    access_token = create_access_token(identity=guest_identity, additional_claims=additional_claims, expires_delta=timedelta(hours=24))

    return jsonify(access_token=access_token), 200

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    existing_user = User.query.filter(
        (User.emailAddress == data['emailAddress']) |
        (User.name == data['name'])
    ).first()

    if existing_user:
        return jsonify({'message': 'A user with that email or username already exists.'}), 400

    new_user = User(
        userId=str(uuid.uuid4()),
        name=data['name'],
        emailAddress=data['emailAddress'],
        forceRelogin=False
    )

    new_user.set_password(data['password'])

    db.session.add(new_user)
    db.session.commit()

    default_role = UserRole(userRoleId=str(uuid.uuid4()), name='user', userId=new_user.userId)
    new_user.roles.append(default_role)

    db.session.commit()

    return jsonify({'message': 'User created successfully.'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(name=data['name']).first()

    if not user:
        return jsonify({'message': 'User not found.'}), 404

    if not user or not user.check_password(data['password']):
        return jsonify({'message': 'Invalid username or password'}), 401

    user.forceRelogin = False
    db.session.commit()

    issuer = 'simkyt'
    audience = 'TrustedClient'

    additional_claims = {
        'iss': issuer,
        'aud': audience,
        'roles': [role.name for role in user.roles]
    }

    access_token = create_access_token(identity={'userId': user.userId, 'name': user.name}, additional_claims=additional_claims, expires_delta=timedelta(hours=24))
    refresh_token = create_refresh_token(identity={'userId': user.userId}, expires_delta=timedelta(hours=24))

    return jsonify(access_token=access_token, refresh_token=refresh_token), 200

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    current_user_identity = get_jwt_identity()
    user = User.query.filter_by(userId=current_user_identity['userId']).first()

    if not user:
        return jsonify({'message': 'User not found.'}), 404

    user.forceRelogin = True
    db.session.commit()

    return jsonify({'message': 'User logged out successfully.'}), 200

@app.route('/api/accessToken', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    user = User.query.filter_by(userId=current_user['userId']).first()

    if not user:
        return jsonify({'message': 'User not found.'}), 404

    if user.forceRelogin:
        return jsonify({'message': 'Re-login required.'}), 403

    issuer = 'simkyt'
    audience = 'TrustedClient'

    additional_claims = {
        'iss': issuer,
        'aud': audience,
        'roles': [role.name for role in user.roles]
    }

    new_access_token = create_access_token(identity={'userId': user.userId, 'name': user.name}, additional_claims=additional_claims, expires_delta=timedelta(minutes=10))
    new_refresh_token = create_refresh_token(identity={'userId': user.userId}, expires_delta=timedelta(hours=24))

    return jsonify(access_token=new_access_token, refresh_token=new_refresh_token), 200

@app.errorhandler(BadRequest)
def handle_bad_request_error(e):
    if 'JWT' in str(e):
        if 'expired' in str(e):
            return jsonify(message="Token has expired"), 401
        else:
            return jsonify(message="Invalid token"), 401
    else:
        return jsonify(message=str(e)), 400

################################################################################################################################################

@app.route('/api/categories', methods=['GET'])
@jwt_required()
def get_categories():
    try:
        current_user_identity = get_jwt_identity()
        current_user_roles = get_jwt()["roles"]

        if 'guest' in current_user_roles:
            categories = Category.query.all()
            return make_response(jsonify([category.json() for category in categories]), 200)

        current_user_id = current_user_identity['userId'] if current_user_identity['userId'] else None
        current_user = User.query.filter_by(userId=current_user_id).first()

        if not current_user:
            return jsonify({'message': f'User not found. {current_user_id}'}), 404

        if current_user.forceRelogin:
            return jsonify({'message': 'Re-login required.'}), 403

        if 'user' not in current_user_roles and 'admin' not in current_user_roles:
            return jsonify({'message': 'Access denied: User does not have the required role'}), 403

        categories = Category.query.all()
        return make_response(jsonify([category.json() for category in categories]), 200)

    except Exception as e:
        return make_response(jsonify({'message': f'error getting categories: {str(e)}'}), 500)

@app.route('/api/categories', methods=['POST'])
@jwt_required()
def create_category():
    try:
        current_user_identity = get_jwt_identity()
        current_user_id = current_user_identity['userId'] if current_user_identity['userId'] else None
        current_user = User.query.filter_by(userId=current_user_id).first()
        current_user_roles = get_jwt()["roles"]

        if not current_user:
            return jsonify({'message': 'User not found.'}), 404

        if current_user.forceRelogin:
            return jsonify({'message': 'Re-login required.'}), 403

        if 'admin' not in current_user_roles:
            return jsonify({'message': 'Access denied: User does not have the required role'}), 403

        data = request.get_json(silent=True)
        if data is None:
            return make_response(jsonify({'message': 'Invalid JSON'}), 400)

        is_valid, validation_message, status_code = validate_category_create(data)
        if not is_valid:
            return make_response(jsonify({'message': validation_message}), status_code)

        new_category = Category(name=data['name'], description=data['description'])
        db.session.add(new_category)
        db.session.commit()
        return make_response(jsonify({'message': 'category created'}), 201)

    except IntegrityError as e:
        db.session.rollback()
        return make_response(jsonify({'message': 'Category with this name and/or description already exists'}), 400)
    except Exception as e:
        return make_response(jsonify({'message': f'error creating category: {str(e)}'}), 500)

@app.route('/api/categories/<int:category_id>', methods=['GET'])
@jwt_required()
def get_category(category_id):
    try:
        current_user_identity = get_jwt_identity()
        current_user_roles = get_jwt()["roles"]

        if 'guest' in current_user_roles:
            category = Category.query.filter_by(id=category_id).first()
            if category:
                return make_response(jsonify({'category': category.json()}), 200)
            return make_response(jsonify({'message': 'category not found'}), 404)

        current_user_id = current_user_identity['userId'] if current_user_identity['userId'] else None
        current_user = User.query.filter_by(userId=current_user_id).first()

        if not current_user:
            return jsonify({'message': 'User not found.'}), 404

        if current_user.forceRelogin:
            return jsonify({'message': 'Re-login required.'}), 403

        if 'user' not in current_user_roles and 'admin' not in current_user_roles:
            return jsonify({'message': 'Access denied: User does not have the required role'}), 403

        category = Category.query.filter_by(id=category_id).first()
        if category:
            return make_response(jsonify({'category': category.json()}), 200)
        return make_response(jsonify({'message': 'category not found'}), 404)
    except Exception as e:
        return make_response(jsonify({'message': f'error getting category: {str(e)}'}), 500)

@app.route('/api/categories/<int:category_id>', methods=['DELETE'])
@jwt_required()
def delete_category(category_id):
    try:
        current_user_identity = get_jwt_identity()
        current_user_id = current_user_identity['userId'] if current_user_identity['userId'] else None
        current_user = User.query.filter_by(userId=current_user_id).first()
        current_user_roles = get_jwt()["roles"]

        if not current_user:
            return jsonify({'message': 'User not found.'}), 404

        if current_user.forceRelogin:
            return jsonify({'message': 'Re-login required.'}), 403

        if 'admin' not in current_user_roles:
            return jsonify({'message': 'Access denied: User does not have the required role'}), 403

        category = Category.query.filter_by(id=category_id).first()
        if category:
            db.session.delete(category)
            db.session.commit()
            return make_response(jsonify({'message': 'category deleted'}), 204)
        return make_response(jsonify({'message': 'category not found'}), 404)
    except Exception as e:
        return make_response(jsonify({'message': f'error deleting category: {str(e)}'}), 500)


@app.route('/api/categories/<int:category_id>', methods=['PUT'])
@jwt_required()
def update_category(category_id):
    try:
        current_user_identity = get_jwt_identity()
        current_user_id = current_user_identity['userId'] if current_user_identity['userId'] else None
        current_user = User.query.filter_by(userId=current_user_id).first()
        current_user_roles = get_jwt()["roles"]

        if not current_user:
            return jsonify({'message': 'User not found.'}), 404

        if current_user.forceRelogin:
            return jsonify({'message': 'Re-login required.'}), 403

        if 'admin' not in current_user_roles:
            return jsonify({'message': 'Access denied: User does not have the required role'}), 403

        data = request.get_json(silent=True)
        if data is None:
            return make_response(jsonify({'message': 'Invalid JSON'}), 400)

        is_valid, validation_message, status_code = validate_category_update(data)
        if not is_valid:
            return make_response(jsonify({'message': validation_message}), status_code)

        category = Category.query.filter_by(id=category_id).first()
        if category:
            category.name = data.get('name', category.name)
            category.description = data.get('description', category.description)
            db.session.commit()
            return make_response(jsonify({'message': 'category updated'}), 200)
        return make_response(jsonify({'message': 'category not found'}), 404)
    except IntegrityError as e:
        db.session.rollback()
        return make_response(jsonify({'message': 'Category with this name and/or description already exists'}), 400)
    except Exception as e:
        return make_response(jsonify({'message': f'error updating category: {str(e)}'}), 500)


def validate_category_create(data):
    try:
        required_fields = {'name', 'description'}

        if not all(field in data for field in required_fields):
            return False, 'Some required fields are missing', 400

        if not set(data.keys()).issubset(required_fields):
            unexpected_fields = set(data.keys()) - required_fields
            return False, f'Unexpected field(s): {", ".join(unexpected_fields)}', 400

        if not isinstance(data['name'], str) or not 0 < len(data['name']) <= 25:
            return False, 'Name must be a non-empty string of maximum 25 characters', 422

        if not isinstance(data['description'], str) or not 0 < len(data['description']) <= 100:
            return False, 'Description must be a non-empty string of maximum 100 characters', 422

        return True, 'Data is valid', 200
    except Exception as e:
        return False, f'Error validating data: {str(e)}', 400


def validate_category_update(data):
    try:
        expected_fields = {'name', 'description'}

        if not set(data.keys()).issubset(expected_fields):
            unexpected_fields = set(data.keys()) - expected_fields
            return False, f'Unexpected field(s): {", ".join(unexpected_fields)}', 400

        if 'name' in data and (not isinstance(data['name'], str) or not 0 < len(data['name']) <= 25):
            return False, 'Name must be a non-empty string of maximum 25 characters', 422

        if 'description' in data and (
                not isinstance(data['description'], str) or not 0 < len(data['description']) <= 100):
            return False, 'Description must be a non-empty string of maximum 100 characters', 422

        return True, 'Data is valid', 200
    except Exception as e:
        return False, f'Error validating data: {str(e)}', 400


################################################################################################################################################

@app.route('/api/categories/<int:category_id>/subcategories', methods=['GET'])
@jwt_required()
def get_subcategories(category_id):
    try:
        current_user_identity = get_jwt_identity()
        current_user_roles = get_jwt()["roles"]

        if 'guest' in current_user_roles:
            category = Category.query.filter_by(id=category_id).first()
            if not category:
                return make_response(jsonify({'message': 'category not found'}), 404)

            subcategories = SubCategory.query.filter_by(category_id=category_id).all()
            return make_response(jsonify([subcategory.json() for subcategory in subcategories]), 200)

        current_user_id = current_user_identity['userId'] if current_user_identity['userId'] else None
        current_user = User.query.filter_by(userId=current_user_id).first()

        if not current_user:
            return jsonify({'message': f'User not found.'}), 404

        if current_user.forceRelogin:
            return jsonify({'message': 'Re-login required.'}), 403

        if 'user' not in current_user_roles and 'admin' not in current_user_roles:
            return jsonify({'message': 'Access denied: User does not have the required role'}), 403

        category = Category.query.filter_by(id=category_id).first()
        if not category:
            return make_response(jsonify({'message': 'category not found'}), 404)

        subcategories = SubCategory.query.filter_by(category_id=category_id).all()
        return make_response(jsonify([subcategory.json() for subcategory in subcategories]), 200)
    except Exception as e:
        return make_response(jsonify({'message': f'error getting subcategories: {str(e)}'}), 500)

@app.route('/api/categories/<int:category_id>/subcategories', methods=['POST'])
@jwt_required()
def create_subcategory(category_id):
    try:
        current_user_identity = get_jwt_identity()
        current_user_id = current_user_identity['userId'] if current_user_identity['userId'] else None
        current_user = User.query.filter_by(userId=current_user_id).first()
        current_user_roles = get_jwt()["roles"]

        if not current_user:
            return jsonify({'message': 'User not found.'}), 404

        if current_user.forceRelogin:
            return jsonify({'message': 'Re-login required.'}), 403

        if 'admin' not in current_user_roles:
            return jsonify({'message': 'Access denied: User does not have the required role'}), 403

        category = Category.query.filter_by(id=category_id).first()
        if not category:
            return make_response(jsonify({'message': 'category not found'}), 404)

        data = request.get_json(silent=True)
        if data is None:
            return make_response(jsonify({'message': 'Invalid JSON'}), 400)

        is_valid, validation_message, status_code = validate_subcategory_create(data)
        if not is_valid:
            return make_response(jsonify({'message': validation_message}), status_code)

        new_subcategory = SubCategory(name=data['name'], description=data['description'], category_id=category_id)
        db.session.add(new_subcategory)
        db.session.commit()
        return make_response(jsonify({'message': 'subcategory created'}), 201)
    except IntegrityError as e:
        db.session.rollback()
        return make_response(jsonify({'message': 'Subcategory with this name and/or description already exists'}), 400)
    except Exception as e:
        return make_response(jsonify({'message': f'error creating subcategory: {str(e)}'}), 500)

@app.route('/api/categories/<int:category_id>/subcategories/<int:subcategory_id>', methods=['GET'])
@jwt_required()
def get_subcategory(category_id, subcategory_id):
    try:
        current_user_identity = get_jwt_identity()
        current_user_roles = get_jwt()["roles"]

        if 'guest' in current_user_roles:
            category = Category.query.filter_by(id=category_id).first()
            if not category:
                return make_response(jsonify({'message': 'category not found'}), 404)

            subcategory = SubCategory.query.filter_by(id=subcategory_id, category_id=category_id).first()
            if subcategory:
                return make_response(jsonify({'subcategory': subcategory.json()}), 200)
            return make_response(jsonify({'message': 'subcategory not found'}), 404)

        current_user_id = current_user_identity['userId'] if current_user_identity['userId'] else None
        current_user = User.query.filter_by(userId=current_user_id).first()

        if not current_user:
            return jsonify({'message': 'User not found.'}), 404

        if current_user.forceRelogin:
            return jsonify({'message': 'Re-login required.'}), 403

        if 'user' not in current_user_roles and 'admin' not in current_user_roles:
            return jsonify({'message': 'Access denied: User does not have the required role'}), 403

        category = Category.query.filter_by(id=category_id).first()
        if not category:
            return make_response(jsonify({'message': 'category not found'}), 404)

        subcategory = SubCategory.query.filter_by(id=subcategory_id, category_id=category_id).first()
        if subcategory:
            return make_response(jsonify({'subcategory': subcategory.json()}), 200)
        return make_response(jsonify({'message': 'subcategory not found'}), 404)

    except Exception as e:
        return make_response(jsonify({'message': f'error getting subcategory: {str(e)}'}), 500)

@app.route('/api/categories/<int:category_id>/subcategories/<int:subcategory_id>', methods=['DELETE'])
@jwt_required()
def delete_subcategory(category_id, subcategory_id):
    try:
        current_user_identity = get_jwt_identity()
        current_user_id = current_user_identity['userId'] if current_user_identity['userId'] else None
        current_user = User.query.filter_by(userId=current_user_id).first()
        current_user_roles = get_jwt()["roles"]

        if not current_user:
            return jsonify({'message': 'User not found.'}), 404

        if current_user.forceRelogin:
            return jsonify({'message': 'Re-login required.'}), 403

        if 'admin' not in current_user_roles:
            return jsonify({'message': 'Access denied: User does not have the required role'}), 403

        category = Category.query.filter_by(id=category_id).first()
        if not category:
            return make_response(jsonify({'message': 'category not found'}), 404)

        subcategory = SubCategory.query.filter_by(id=subcategory_id, category_id=category_id).first()
        if subcategory:
            db.session.delete(subcategory)
            db.session.commit()
            return make_response(jsonify({'message': 'subcategory deleted'}), 204)
        return make_response(jsonify({'message': 'subcategory not found or does not belong to the specified category'}), 404)
    except Exception as e:
        return make_response(jsonify({'message': f'error deleting subcategory: {str(e)}'}), 500)

@app.route('/api/categories/<int:category_id>/subcategories/<int:subcategory_id>', methods=['PUT'])
@jwt_required()
def update_subcategory(category_id, subcategory_id):
    try:
        current_user_identity = get_jwt_identity()
        current_user_id = current_user_identity['userId'] if current_user_identity['userId'] else None
        current_user = User.query.filter_by(userId=current_user_id).first()
        current_user_roles = get_jwt()["roles"]

        if not current_user:
            return jsonify({'message': 'User not found.'}), 404

        if current_user.forceRelogin:
            return jsonify({'message': 'Re-login required.'}), 403

        if 'admin' not in current_user_roles:
            return jsonify({'message': 'Access denied: User does not have the required role'}), 403

        category = Category.query.filter_by(id=category_id).first()
        if not category:
            return make_response(jsonify({'message': 'category not found'}), 404)

        subcategory = SubCategory.query.filter_by(id=subcategory_id, category_id=category_id).first()
        if subcategory:
            data = request.get_json(silent=True)
            if data is None:
                return make_response(jsonify({'message': 'Invalid JSON'}), 400)

            is_valid, validation_message, status_code = validate_subcategory_update(data)
            if not is_valid:
                return make_response(jsonify({'message': validation_message}), status_code)

            new_category_id = data.get('category_id', category_id)
            if new_category_id != category_id and not Category.query.get(new_category_id):
                return make_response(jsonify({'message': 'new category not found'}), 400)

            subcategory.name = data.get('name', subcategory.name)
            subcategory.description = data.get('description', subcategory.description)
            subcategory.category_id = new_category_id

            db.session.commit()
            return make_response(jsonify({'message': 'subcategory updated'}), 200)
        return make_response(jsonify({'message': 'subcategory not found or does not belong to the specified category'}), 404)
    except IntegrityError as e:
        db.session.rollback()
        return make_response(jsonify({'message': 'Subcategory with this name and/or description already exists'}), 400)
    except Exception as e:
        return make_response(jsonify({'message': f'error updating subcategory: {str(e)}'}), 500)


def validate_subcategory_create(data):
    try:
        required_fields = {'name', 'description'}

        if not all(field in data for field in required_fields):
            return False, 'Some required fields are missing', 400

        if not set(data.keys()).issubset(required_fields):
            unexpected_fields = set(data.keys()) - required_fields
            return False, f'Unexpected field(s): {", ".join(unexpected_fields)}', 400

        if not isinstance(data['name'], str) or not 0 < len(data['name']) <= 25:
            return False, 'Name must be a non-empty string of maximum 25 characters', 422

        if not isinstance(data['description'], str) or not 0 < len(data['description']) <= 100:
            return False, 'Description must be a non-empty string of maximum 100 characters', 422

        return True, 'Data is valid', 200
    except Exception as e:
        return False, f'Error validating data: {str(e)}', 400


def validate_subcategory_update(data):
    try:
        expected_fields = {'name', 'description', 'category_id'}

        if not set(data.keys()).issubset(expected_fields):
            unexpected_fields = set(data.keys()) - expected_fields
            return False, f'Unexpected field(s): {", ".join(unexpected_fields)}', 400

        if 'name' in data and (not isinstance(data['name'], str) or not 0 < len(data['name']) <= 25):
            return False, 'Name must be a non-empty string of maximum 25 characters', 422

        if 'description' in data and (
                not isinstance(data['description'], str) or not 0 < len(data['description']) <= 100):
            return False, 'Description must be a non-empty string of maximum 100 characters', 422

        if 'category_id' in data and not isinstance(data['category_id'], int):
            return False, 'category_id must be an integer', 422

        return True, 'Data is valid', 200
    except Exception as e:
        return False, f'Error validating data: {str(e)}', 400


################################################################################################################################################

@app.route('/api/foods', methods=['GET'])
@jwt_required()
def get_all_foods():
    try:
        current_user_identity = get_jwt_identity()
        current_user = User.query.filter_by(userId=current_user_identity['userId']).first()
        current_user_roles = get_jwt()["roles"]

        if not current_user:
            return jsonify({'message': 'User not found.'}), 404

        if current_user.forceRelogin:
            return jsonify({'message': 'Re-login required.'}), 403

        if 'user' not in current_user_roles and 'admin' not in current_user_roles:
            return jsonify({'message': 'Access denied: User does not have the required role'}), 403

        # Retrieve query parameters
        food_name = request.args.get('search', '')
        page = request.args.get('page', 1, type=int)

        # Query the database with filter and pagination
        food_query = Food.query.filter(Food.name.ilike(f'%{food_name}%')).paginate(page=page, per_page=20, error_out=False)
        foods = [food.json() for food in food_query.items]

        return make_response(jsonify(foods), 200)

    except Exception as e:
        return make_response(jsonify({'message': f'error getting foods: {str(e)}'}), 500)

@app.route('/api/categories/<int:category_id>/subcategories/<int:subcategory_id>/foods', methods=['GET'])
@jwt_required()
def get_foods(category_id, subcategory_id):
    try:
        current_user_identity = get_jwt_identity()
        current_user = User.query.filter_by(userId=current_user_identity['userId']).first()
        current_user_roles = get_jwt()["roles"]

        if not current_user:
            return jsonify({'message': 'User not found.'}), 404

        if current_user.forceRelogin:
            return jsonify({'message': 'Re-login required.'}), 403

        if 'user' not in current_user_roles and 'admin' not in current_user_roles:
            return jsonify({'message': 'Access denied: User does not have the required role'}), 403

        category = Category.query.get(category_id)
        if not category:
            return make_response(jsonify({'message': 'Category not found'}), 404)

        subcategory = SubCategory.query.get(subcategory_id)
        if not subcategory or subcategory.category_id != category_id:
            return make_response(
                jsonify({'message': 'Subcategory not found or does not belong to the specified category'}), 404)

        foods = [food.json() for food in subcategory.foods]
        return make_response(jsonify(foods), 200)

    except Exception as e:
        return make_response(jsonify({'message': f'error getting foods: {str(e)}'}), 500)


@app.route('/api/categories/<int:category_id>/subcategories/<int:subcategory_id>/foods', methods=['POST'])
@jwt_required()
def create_food(category_id, subcategory_id):
    try:
        current_user_identity = get_jwt_identity()
        current_user = User.query.filter_by(userId=current_user_identity['userId']).first()
        current_user_roles = get_jwt()["roles"]

        if not current_user:
            return jsonify({'message': 'User not found.'}), 404

        if current_user.forceRelogin:
            return jsonify({'message': 'Re-login required.'}), 403

        if 'user' not in current_user_roles and 'admin' not in current_user_roles:
            return jsonify({'message': 'Access denied: User does not have the required role'}), 403

        category = Category.query.filter_by(id=category_id).first()
        if not category:
            return make_response(jsonify({'message': 'category not found'}), 404)

        subcategory = SubCategory.query.get(subcategory_id)
        if not subcategory or subcategory.category_id != category_id:
            return make_response(
                jsonify({'message': 'Subcategory not found or does not belong to the specified category'}), 404)

        data = request.get_json(silent=True)
        if data is None:
            return make_response(jsonify({'message': 'Invalid JSON'}), 400)

        is_valid, validation_message, status_code = validate_data(data)

        if not is_valid:
            return make_response(jsonify({'message': validation_message}), status_code)

        new_food = Food(
            id=data['id'],
            name=data['name'], brand=data.get('brand', None),
            kcal=data['kcal'], carbs=data['carbs'],
            fat=data['fat'], protein=data['protein'],
            serving=data['serving'], perserving=data['perserving'],
            size=data['size'], subcategory_id=subcategory_id,
            user=current_user.userId
        )
        db.session.add(new_food)
        db.session.commit()
        return make_response(jsonify({'message': 'Food created'}), 201)

    except KeyError as e:
        return make_response(jsonify({'message': f'Missing field: {str(e)}'}), 422)
    except Exception as e:
        return make_response(jsonify({'message': f'error creating food: {str(e)}'}), 500)

@app.route('/api/categories/<int:category_id>/subcategories/<int:subcategory_id>/foods/<string:food_id>', methods=['GET'])
@jwt_required()
def get_food(category_id, subcategory_id, food_id):
    current_user_identity = get_jwt_identity()
    current_user = User.query.filter_by(userId=current_user_identity['userId']).first()
    current_user_roles = get_jwt()["roles"]

    if not current_user:
        return jsonify({'message': 'User not found.'}), 404

    if current_user.forceRelogin:
        return jsonify({'message': 'Re-login required.'}), 403

    if 'user' not in current_user_roles and 'admin' not in current_user_roles:
        return jsonify({'message': 'Access denied: User does not have the required role'}), 403

    try:
        category = Category.query.filter_by(id=category_id).first()
        if not category:
            return make_response(jsonify({'message': 'category not found'}), 404)

        subcategory = SubCategory.query.get(subcategory_id)
        if not subcategory or subcategory.category_id != category_id:
            return make_response(
                jsonify({'message': 'Subcategory not found or does not belong to the specified category'}), 404)

        food = Food.query.get(food_id)
        if not food or food.subcategory_id != subcategory_id:
            return make_response(jsonify({'message': 'Food not found or does not belong to the specified subcategory'}),
                                 404)

        return make_response(jsonify(food.json()), 200)
    except Exception as e:
        return make_response(jsonify({'message': f'error getting food: {str(e)}'}), 500)

@app.route('/api/categories/<int:category_id>/subcategories/<int:subcategory_id>/foods/<string:food_id>', methods=['DELETE'])
@jwt_required()
def delete_food(category_id, subcategory_id, food_id):
    try:
        current_user_identity = get_jwt_identity()
        current_user = User.query.filter_by(userId=current_user_identity['userId']).first()
        current_user_roles = get_jwt()["roles"]

        if not current_user:
            return jsonify({'message': 'User not found.'}), 404

        if current_user.forceRelogin:
            return jsonify({'message': 'Re-login required.'}), 403

        if 'admin' not in current_user_roles:
            return jsonify({'message': 'Access denied: User does not have the required role'}), 403

        category = Category.query.filter_by(id=category_id).first()
        if not category:
            return make_response(jsonify({'message': 'category not found'}), 404)

        subcategory = SubCategory.query.get(subcategory_id)
        if not subcategory or subcategory.category_id != category_id:
            return make_response(
                jsonify({'message': 'Subcategory not found or does not belong to the specified category'}), 404)

        food = Food.query.get(food_id)
        if not food or food.subcategory_id != subcategory_id:
            return make_response(jsonify({'message': 'Food not found or does not belong to the specified subcategory'}),
                                 404)

        db.session.delete(food)
        db.session.commit()
        return make_response(jsonify({'message': 'Food deleted'}), 204)
    except Exception as e:
        return make_response(jsonify({'message': f'error deleting food: {str(e)}'}), 500)


@app.route('/api/categories/<int:category_id>/subcategories/<int:subcategory_id>/foods/<string:food_id>', methods=['PUT'])
@jwt_required()
def update_food(category_id, subcategory_id, food_id):
    try:
        current_user_identity = get_jwt_identity()
        current_user = User.query.filter_by(userId=current_user_identity['userId']).first()
        current_user_roles = get_jwt()["roles"]

        if not current_user:
            return jsonify({'message': 'User not found.'}), 404

        if current_user.forceRelogin:
            return jsonify({'message': 'Re-login required.'}), 403

        if 'user' not in current_user_roles and 'admin' not in current_user_roles:
            return jsonify({'message': 'Access denied: User does not have the required role'}), 403

        category = Category.query.get(category_id)
        if not category:
            return make_response(jsonify({'message': 'Category not found'}), 404)

        subcategory = SubCategory.query.get(subcategory_id)
        if not subcategory or subcategory.category_id != category_id:
            return make_response(
                jsonify({'message': 'Subcategory not found or does not belong to the specified category'}), 404)

        food = Food.query.get(food_id)
        if not food or food.subcategory_id != subcategory_id:
            return make_response(jsonify({'message': 'Food not found or does not belong to the specified subcategory'}),
                                 404)

        if food.user != current_user.userId and 'admin' not in current_user_roles:
            return make_response(jsonify({'message': 'Access denied: User is not the creator of the food item and is not an admin'}), 403)

        data = request.get_json(silent=True)
        if data is None:
            return make_response(jsonify({'message': 'Invalid JSON'}), 400)

        is_valid, validation_message, status_code = validate_update_data(data)

        if not is_valid:
            return make_response(jsonify({'message': validation_message}), status_code)

        food.name = data.get('name', food.name)
        food.brand = data.get('brand', food.brand)
        food.kcal = data.get('kcal', food.kcal)
        food.carbs = data.get('carbs', food.carbs)
        food.fat = data.get('fat', food.fat)
        food.protein = data.get('protein', food.protein)
        food.serving = data.get('serving', food.serving)
        food.perserving = data.get('perserving', food.perserving)
        food.size = data.get('size', food.size)

        if 'subcategory_id' in data:
            new_subcategory = SubCategory.query.get(data['subcategory_id'])
            if not new_subcategory:
                return make_response(
                    jsonify({'message': 'New subcategory not found'}), 404)
            food.subcategory_id = data['subcategory_id']

        db.session.commit()
        return make_response(jsonify(food.json()), 200)

    except Exception as e:
        return make_response(jsonify({'message': f'error updating food: {str(e)}'}), 500)


def validate_data(data):
    try:
        required_fields = {'id', 'name', 'brand', 'kcal', 'carbs', 'fat', 'protein', 'serving', 'perserving', 'size'}
        allowed_fields = required_fields.union({'subcategory_id'})

        if not all(field in data for field in required_fields):
            return False, 'Some required fields are missing', 400

        if not set(data.keys()).issubset(allowed_fields):
            unexpected_fields = set(data.keys()) - allowed_fields
            return False, f'Unexpected field(s): {", ".join(unexpected_fields)}', 400


        if not isinstance(data['id'], str):
            return False, 'ID must be a string', 422
        if not isinstance(data['name'], str):
            return False, 'Name must be a string', 422
        if not isinstance(data['brand'], str):
            return False, 'Brand must be a string', 422
        if not (isinstance(data['kcal'], int) or isinstance(data['kcal'], float)):
            return False, 'kcal must be a number', 422
        if not (isinstance(data['carbs'], int) or isinstance(data['carbs'], float)):
            return False, 'carbs must be a number', 422
        if not (isinstance(data['fat'], int) or isinstance(data['fat'], float)):
            return False, 'fat must be a number', 422
        if not (isinstance(data['protein'], int) or isinstance(data['protein'], float)):
            return False, 'protein must be a number', 422
        if not isinstance(data['serving'], str):
            return False, 'serving must be a string', 422
        if not isinstance(data['perserving'], str):
            return False, 'perserving must be a string', 422
        if not (isinstance(data['size'], int) or isinstance(data['size'], float)):
            return False, 'size must be a number', 422

        return True, 'Data is valid', 200
    except Exception as e:
        return False, f'Error validating data: {str(e)}', 400


def validate_update_data(data):
    try:
        expected_fields = {'subcategory_id', 'name', 'brand', 'kcal', 'carbs', 'fat', 'protein', 'serving', 'perserving', 'size'}
        allowed_fields = expected_fields.union({'id'})

        if not set(data.keys()).issubset(allowed_fields):
            unexpected_fields = set(data.keys()) - allowed_fields
            return False, f'Unexpected field(s): {", ".join(unexpected_fields)}', 400

        if 'subcategory_id' in data and not isinstance(data['subcategory_id'], int):
            return False, 'Subcategory ID must be a number', 422
        if 'name' in data and not isinstance(data['name'], str):
            return False, 'Name must be a string', 422
        if 'brand' in data and not isinstance(data['brand'], str):
            return False, 'Brand must be a string', 422
        if 'kcal' in data and not (isinstance(data['kcal'], int) or isinstance(data['kcal'], float)):
            return False, 'kcal must be a number', 422
        if 'carbs' in data and not (isinstance(data['carbs'], int) or isinstance(data['carbs'], float)):
            return False, 'carbs must be a number', 422
        if 'fat' in data and not (isinstance(data['fat'], int) or isinstance(data['fat'], float)):
            return False, 'fat must be a number', 422
        if 'protein' in data and not (isinstance(data['protein'], int) or isinstance(data['protein'], float)):
            return False, 'protein must be a number', 422
        if 'serving' in data and not isinstance(data['serving'], str):
            return False, 'serving must be a string', 422
        if 'perserving' in data and not isinstance(data['perserving'], str):
            return False, 'perserving must be a string', 422
        if 'size' in data and not (isinstance(data['size'], int) or isinstance(data['size'], float)):
            return False, 'size must be a number', 422

        return True, 'Data is valid', 200
    except Exception as e:
        return False, f'Error validating data: {str(e)}', 400



