from bson import ObjectId
from flask import Flask, request, redirect, url_for, render_template, session, jsonify, flash
import os
import json

from openapi_spec_validator.validation.exceptions import OpenAPIValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from openai import OpenAI
from openapi_spec_validator import validate_spec
from openai_config import setup_openai
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from mongo_config import get_database
import requests

# Obtener la base de datos de servicios
db = get_database()
# Obtener la colección de servicios de restaurantes
collection = db.restaurant

#obtener la bbdd de usuarios
db_users = get_database("users")
user_collection = db_users.users

client = OpenAI()

# Configura tu clave API de OpenAI
model_engine = setup_openai()

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'json'}

# Definir la URL base de la API REST
API_BASE_URL = 'http://127.0.0.1:5000'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
@login_required
def index():
    return render_template('home.html')

@app.route('/uploadopenapi')
@login_required
def uploadopenapi():
    return render_template('index.html')

@app.route('/home')
@login_required
def home():
    return render_template('create_spec.html')

#Crear un servicio OPENAPI DESDE 0
@app.route('/create_spec', methods=['GET', 'POST'])
@login_required
def create_spec():
    if request.method == 'POST':
        session['spec_data'] = {
            'openapi': '3.0.0',
            'info': {
                'title': request.form['title'],
                'version': request.form['version'],
                'description': request.form['description'],
                'contact': {
                    'email': current_user.email  # Usar el correo electrónico del usuario actual
                }
            },
            'paths': {},
            'components': {
                'schemas': {}
            }
        }
        return redirect(url_for('add_endpoint'))
    return render_template('create_spec.html')

@app.route('/add_schema', methods=['GET', 'POST'])
@login_required
def add_schema():
    if request.method == 'POST':
        schema_name = request.form['schema_name']
        properties_input = request.form['properties']
        properties = {}

        for prop in properties_input.split(','):
            name, type_ = prop.split(':')
            properties[name.strip()] = {'type': type_.strip()}

        schema_data = {
            'type': 'object',
            'properties': properties
        }

        spec_data = session.get('spec_data', {})
        spec_data['components']['schemas'][schema_name] = schema_data
        session['spec_data'] = spec_data

        return redirect(url_for('add_schema'))

    return render_template('add_schema.html')

@app.route('/add_endpoint', methods=['GET', 'POST'])
@login_required
def add_endpoint():
    if request.method == 'POST':
        path = request.form['path']
        method = request.form['method']
        summary = request.form['summary']
        description = request.form['description']
        request_body_schema = request.form.get('request_body_schema')

        endpoint_data = {
            method: {
                'summary': summary,
                'description': description,
                'parameters': [],
                'responses': {
                    '200': {
                        'description': 'Success'
                    }
                }
            }
        }

        if request_body_schema:
            endpoint_data[method]['requestBody'] = {
                'description': 'Request body for ' + summary,
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {
                            '$ref': f'#/components/schemas/{request_body_schema}'
                        }
                    }
                }
            }

        spec_data = session.get('spec_data', {})
        if 'paths' not in spec_data:
            spec_data['paths'] = {}
        if path not in spec_data['paths']:
            spec_data['paths'][path] = {}

        spec_data['paths'][path].update(endpoint_data)
        session['spec_data'] = spec_data

        if request_body_schema:
            return redirect(url_for('add_schema'))
        else:
            session['current_endpoint'] = (path, method)
            return redirect(url_for('add_parameters'))

    return render_template('add_endpoint.html')

@app.route('/add_parameters', methods=['GET', 'POST'])
@login_required
def add_parameters():
    if request.method == 'POST':
        name = request.form['name']
        param_in = request.form['in']
        param_type = request.form['type']
        enum_values = request.form['enum']
        description = request.form['description']

        param_data = {
            'name': name,
            'in': param_in,
            'description': description,
            'schema': {
                'type': param_type
            }
        }

        if enum_values:
            param_data['schema']['enum'] = [v.strip() for v in enum_values.split(',')]

        spec_data = session.get('spec_data', {})
        path, method = session.get('current_endpoint')
        spec_data['paths'][path][method]['parameters'].append(param_data)
        session['spec_data'] = spec_data

        return redirect(url_for('add_parameters'))

    return render_template('add_parameters.html')

@app.route('/finish_spec_creation')
@login_required
def finish_spec_creation():
    return redirect(url_for('show_spec_summary'))

@app.route('/show_spec_summary')
@login_required
def show_spec_summary():
    spec_data = session.get('spec_data', {})
    return render_template('spec_summary.html', spec=spec_data)

@app.route('/download_spec', methods=['GET'])
@login_required
def download_spec():
    spec_data = session.get('spec_data', {})
    response = jsonify(spec_data)
    response.headers.set("Content-Disposition", "attachment", filename="openapi_spec.json")
    return response

@app.route('/transform_to_pptalk', methods=['POST'])
@login_required
def transform_to_pptalk():
    updated_spec = session.get('spec_data', {})
    session['updated_spec'] = updated_spec  # Save the spec to be used in the transformation process

    # Extract endpoints and operations
    operations = extract_operations(session['updated_spec'])
    selected_operations = [f"{op[1].upper()} {op[2]}" for op in operations]
    selected_operations_details = [
        {
            'operation': op,
            'parameters': get_parameters(op),
            'questions': generate_questions(get_parameters(op))
        } for op in selected_operations
    ]
    updated_spec = add_questions_to_spec(session.get('spec_data', {}), selected_operations_details)
    session['updated_spec'] = updated_spec
    session['selected_operations'] = selected_operations_details
    return redirect(url_for('extra_info'))

#TRANSFORMAR DE JSON A OPENAPI PPTALK
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    if file and allowed_file(file.filename):
        filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filename)
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            # Validate the JSON content as OpenAPI specification
            validate_spec(data)
            # Añadir el autor a la especificación
            data['info']['contact'] = {
                'email': current_user.email  # Usar el correo electrónico del usuario actual
            }
            # Extract endpoints and operations
            operations = extract_operations(data)
            session['operations'] = operations  # Save operations in session
            session['spec_data'] = data  # Save the OpenAPI spec in session

            # Generate questions for all operations and parameters
            selected_operations = [f"{op[1].upper()} {op[2]}" for op in operations]
            selected_operations_details = [
                {
                    'operation': op,
                    'parameters': get_parameters(op),
                    'questions': generate_questions(get_parameters(op))
                } for op in selected_operations
            ]
            updated_spec = add_questions_to_spec(session.get('spec_data', {}), selected_operations_details)
            session['updated_spec'] = updated_spec  # Save updated spec in session
            session['selected_operations'] = selected_operations_details  # Save selected operations in session
            return redirect(url_for('extra_info'))
        except json.JSONDecodeError:
            os.remove(filename)  # Remove the invalid file
            return 'Invalid JSON file', 400
        except Exception as e:
            os.remove(filename)  # Remove the invalid file
            return f'Invalid OpenAPI specification: {e}', 400
    else:
        return 'Formato de archivo no permitido. Por favor, suba un archivo .json.', 400

def extract_operations(data):
    operations = []
    for path, methods in data.get('paths', {}).items():
        for method, details in methods.items():
            operation_id = details.get('operationId', f"{method.upper()} {path}")
            operations.append((operation_id, method, path))
    return operations

def get_parameters(operation):
    data = session.get('spec_data', {})
    method, path = operation.split(' ', 1)
    parameters = []

    if 'paths' in data and path in data['paths'] and method.lower() in data['paths'][path]:
        method_data = data['paths'][path][method.lower()]

        # Obtener parámetros para cualquier método
        if 'parameters' in method_data:
            parameters.extend(method_data.get('parameters', []))

        # Obtener parámetros específicos para el método POST
        if method.lower() == 'post' and 'requestBody' in method_data:
            content = method_data['requestBody'].get('content', {})
            for content_type, content_schema in content.items():
                if 'schema' in content_schema:
                    schema_ref = content_schema['schema'].get('$ref')
                    if schema_ref:
                        schema_name = schema_ref.split('/')[-1]
                        schema = data['components']['schemas'].get(schema_name, {})
                        properties = schema.get('properties', {})
                        parameters.extend([{'name': k, 'schema': v} for k, v in properties.items()])
                    break

    parameter_names = [param['name'] for param in parameters]
    return parameter_names

def generate_questions(parameters):
    questions = []
    for param in parameters:
        question = call_openai_api(param)
        questions.append(question)
    return questions

def call_openai_api(parameter_name):
    domain = "restaurant"
    #prompt = f"Generate a question to ask a user for the parameter '{parameter_name}' in the {domain} domain."
    prompt = "I am developing a chatbot that users can employ to bookrestaurant in the domain "+domain+". Generate just a question without format that the chatbot can use to ask the user for "+parameter_name
    # Generate a response
    completion = client.completions.create(
        model=model_engine,
        prompt=prompt)
    response = completion.choices[0].text
    return response

def add_questions_to_spec(spec_data, selected_operations_details):
    for op_detail in selected_operations_details:
        method, path = op_detail['operation'].split(' ', 1)
        parameters = op_detail['parameters']
        questions = op_detail['questions']

        if 'paths' in spec_data and path in spec_data['paths'] and method.lower() in spec_data['paths'][path]:
            if method.lower() == 'post':
                # Añadir preguntas a los parámetros
                if 'parameters' not in spec_data['paths'][path][method.lower()]:
                    spec_data['paths'][path][method.lower()]['parameters'] = []
                for i, param in enumerate(parameters):
                    param_exists = False
                    for param_detail in spec_data['paths'][path][method.lower()]['parameters']:
                        if param_detail['name'] == param:
                            param_detail['x-custom-question'] = questions[i]
                            param_exists = True
                            break
                    if not param_exists:
                        spec_data['paths'][path][method.lower()]['parameters'].append({
                            'name': param,
                            'in': 'query',
                            'schema': {'type': 'string'},
                            'x-custom-question': questions[i]
                        })

                # Añadir preguntas al cuerpo de solicitud
                if 'requestBody' in spec_data['paths'][path][method.lower()]:
                    content = spec_data['paths'][path][method.lower()]['requestBody'].get('content', {})
                    for content_type, content_schema in content.items():
                        if 'schema' in content_schema:
                            schema_ref = content_schema['schema'].get('$ref')
                            if schema_ref:
                                schema_name = schema_ref.split('/')[-1]
                                schema = spec_data['components']['schemas'].get(schema_name, {})
                                properties = schema.get('properties', {})
                                for i, param in enumerate(parameters):
                                    if param in properties:
                                        properties[param]['x-custom-question'] = questions[i]
                            break
            else:
                if 'parameters' not in spec_data['paths'][path][method.lower()]:
                    spec_data['paths'][path][method.lower()]['parameters'] = []
                for i, param in enumerate(parameters):
                    param_exists = False
                    for param_detail in spec_data['paths'][path][method.lower()]['parameters']:
                        if param_detail['name'] == param:
                            param_detail['x-custom-question'] = questions[i]
                            param_exists = True
                            break
                    if not param_exists:
                        spec_data['paths'][path][method.lower()]['parameters'].append({
                            'name': param,
                            'in': 'query',
                            'schema': {'type': 'string'},
                            'x-custom-question': questions[i]
                        })
    return spec_data

@app.route('/extra_info', methods=['GET', 'POST'])
@login_required
def extra_info():
    if request.method == 'POST':
        food_type = request.form.get('food_type')
        price_range = request.form.get('price_range')
        updated_spec = session.get('updated_spec', {})

        food_param = {
            "name": "food",
            "in": "query",
            "description": "Type of food desired by the user",
            "required": False,
            "style": "form",
            "explode": True,
            "schema": {
                "example": food_type,
                "type": "string",
                "enum": [
                    "afghan", "african", "afternoon tea", "asian oriental", "australasian",
                    "australian", "austrian", "barbeque", "basque", "belgian", "bistro",
                    "brazilian", "british", "canapes", "cantonese", "caribbean", "catalan",
                    "chinese", "christmas", "corsica", "creative", "crossover", "cuban",
                    "danish", "eastern european", "english", "eritrean", "european", "french",
                    "fusion", "gastropub", "german", "greek", "halal", "hungarian", "indian",
                    "indonesian", "international", "irish", "italian", "jamaican", "japanese",
                    "korean", "kosher", "latin american", "lebanese", "light bites", "malaysian",
                    "mediterranean", "mexican", "middle eastern", "modern american", "modern eclectic",
                    "modern european", "modern global", "molecular gastronomy", "moroccan", "new zealand",
                    "north african", "north american", "north indian", "northern european", "panasian",
                    "persian", "polish", "polynesian", "portuguese", "romanian", "russian", "scandinavian",
                    "scottish", "seafood", "singaporean", "south african", "south indian", "spanish",
                    "sri lankan", "steakhouse", "swedish", "swiss", "thai", "the americas", "traditional",
                    "turkish", "tuscan", "unusual", "vegetarian", "venetian", "vietnamese", "welsh", "world"
                ]
            },
            "x-custom-question": call_openai_api("food")
        }

        price_param = {
            "name": "price_range",
            "in": "query",
            "description": "Price range desired by the user",
            "required": False,
            "style": "form",
            "explode": True,
            "schema": {
                "type": "string",
                "example": price_range,
                "enum": ["cheap", "moderate", "expensive"]
            },
            "x-custom-question": call_openai_api("price range")
        }

        for op_detail in session.get('selected_operations', []):
            method, path = op_detail['operation'].split(' ', 1)
            if 'paths' in updated_spec and path in updated_spec['paths'] and method.lower() in updated_spec['paths'][path]:
                if 'parameters' not in updated_spec['paths'][path][method.lower()]:
                    updated_spec['paths'][path][method.lower()]['parameters'] = []
                updated_spec['paths'][path][method.lower()]['parameters'].append(food_param)
                updated_spec['paths'][path][method.lower()]['parameters'].append(price_param)

        session['updated_spec'] = updated_spec  # Update spec with food info and price info
        return redirect(url_for('add_tags'))
    return render_template('extra_info.html', spec=session.get('updated_spec', {}))


@app.route('/show_updated_spec')
@login_required
def show_updated_spec():
    updated_spec = session.get('updated_spec', {})
    return render_template('show_updated_spec.html', spec=updated_spec)

@app.route('/download', methods=['GET'])
@login_required
def download():
    updated_spec = session.get('updated_spec', {})
    response = jsonify(updated_spec)
    response.headers.set("Content-Disposition", "attachment", filename="updated_spec.json")
    return response

@app.route('/insert_service', methods=['POST'])
@login_required
def insert_service():
    updated_spec = session.get('updated_spec', {})
    if not updated_spec:
        return jsonify({'msg': 'No specification found in session'}), 400

    try:
        # Añadir el autor a la especificación
        if 'contact' not in updated_spec['info']:
            updated_spec['info']['contact'] = {
                'email': current_user.email  # Usar el correo electrónico del usuario actual
            }

        # Inserta la especificación en la colección 'restaurants'
        result = collection.insert_one(updated_spec)
        return jsonify({'msg': 'Specification inserted successfully', 'id': str(result.inserted_id)}), 201
    except Exception as e:
        return jsonify({'msg': 'Error inserting specification', 'error': str(e)}), 500


@app.route('/add_tags', methods=['GET', 'POST'])
@login_required
def add_tags():
    if request.method == 'POST':
        tags_input = request.form.get('tags')

        # Si no se proporcionan etiquetas, simplemente redirige a la especificación actualizada
        if not tags_input or tags_input.strip() == "":
            return redirect(url_for('show_updated_spec'))

        tags = [tag.strip() for tag in tags_input.split(',') if tag.strip()]

        if not tags:
            return 'Invalid tags format. Please provide comma-separated tags.', 400

        updated_spec = session.get('updated_spec', {})

        if 'tags' not in updated_spec:
            updated_spec['tags'] = []

        existing_tags = {tag['name'] for tag in updated_spec['tags']}
        new_tags_str = ', '.join(tags)

        if new_tags_str not in existing_tags:
            updated_spec['tags'].append({'name': new_tags_str})

        session['updated_spec'] = updated_spec
        return redirect(url_for('show_updated_spec'))
    return render_template('add_tags.html')

#LOGIN & USERS#
class User(UserMixin):
    def __init__(self, user_id, email):
        self.id = user_id
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    user = user_collection.find_one({'_id': ObjectId(user_id)})
    if user:
        return User(str(user['_id']), user['email'])
    return None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        user = user_collection.find_one({'email': email})
        if user:
            flash('Email already exists')
            return redirect(url_for('register'))

        user_collection.insert_one({'email': email, 'password': hashed_password})
        flash('Registration successful, please login')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = user_collection.find_one({'email': email})

        if user and check_password_hash(user['password'], password):
            user_obj = User(str(user['_id']), user['email'])
            login_user(user_obj)
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/my_services')
@login_required
def my_services():
    user_email = current_user.email
    try:
        response = requests.get(f'http://127.0.0.1:5000/services/{user_email}')
        response.raise_for_status()  # Lanza un error si la respuesta HTTP tiene un error

        # Imprimir la respuesta para depuración
        print("Response status code:", response.status_code)
        print("Response content:", response.content)

        try:
            services = response.json()
        except requests.exceptions.JSONDecodeError:
            print("Error decoding JSON:", response.text)
            flash('Error decoding response from API')
            services = []
    except requests.exceptions.RequestException as e:
        print("Request failed:", e)
        flash('Error connecting to API')
        services = []

    return render_template('my_services.html', services=services)


@app.route('/view_service/<service_id>')
@login_required
def view_service(service_id):
    try:
        response = requests.get(f'{API_BASE_URL}/service/{service_id}')
        response.raise_for_status()  # Lanza un error si la respuesta HTTP tiene un error

        # Imprimir la respuesta para depuración
        print("Response status code:", response.status_code)
        print("Response content:", response.content)

        try:
            service = response.json()
        except requests.exceptions.JSONDecodeError:
            print("Error decoding JSON:", response.text)
            flash('Error decoding response from API')
            return redirect(url_for('my_services'))

    except requests.exceptions.RequestException as e:
        print("Request failed:", e)
        flash('Error connecting to API')
        return redirect(url_for('my_services'))

    return render_template('view_service.html', service=service)


@app.route('/edit_service/<service_id>', methods=['GET', 'POST'])
@login_required
def edit_service(service_id):
    if request.method == 'POST':
        # Recoger los datos del formulario
        title = request.form['title']
        version = request.form['version']
        description = request.form['description']
        paths = request.form['paths']
        components = request.form['components']

        try:
            # Convertir paths y components de JSON string a diccionario
            paths_dict = json.loads(paths)
            components_dict = json.loads(components)

            # Crear la especificación completa de OpenAPI para validarla
            openapi_spec = {
                'openapi': '3.0.0',
                'info': {
                    'title': title,
                    'version': version,
                    'description': description
                },
                'paths': paths_dict,
                'components': components_dict
            }

            # Validar la especificación de OpenAPI
            validate_spec(openapi_spec)

            # Actualizar el documento en la base de datos
            collection.update_one(
                {'_id': ObjectId(service_id)},
                {'$set': {
                    'info.title': title,
                    'info.version': version,
                    'info.description': description,
                    'paths': paths_dict,
                    'components': components_dict
                }}
            )

            flash('Service updated successfully', 'success')
        except json.JSONDecodeError as e:
            flash(f'Error parsing JSON: {e}', 'danger')
        except OpenAPIValidationError as e:
            flash(f'Invalid OpenAPI specification: {e}', 'danger')

        return redirect(url_for('my_services'))

    # Obtener el servicio desde la base de datos para mostrar en el formulario
    service = collection.find_one({'_id': ObjectId(service_id)})
    return render_template('edit_service.html', service=service)

@app.route('/delete_service/<service_id>', methods=['POST'])
@login_required
def delete_service(service_id):
    response = requests.delete(f'{API_BASE_URL}/service/{service_id}')
    if response.status_code == 200:
        return redirect(url_for('my_services'))
    else:
        flash('Error deleting service')
        return redirect(url_for('my_services'))


if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True, port=5005)