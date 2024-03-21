## healthsquare
### How to run the project:

#### Clone the repository
#### Create a virtual environment python3 -m venv env
#### Activate the virtual environment source env/bin/activate
#### Install the requirements ip3 install -r requirements.txt
#### Create a Postgres database create DATABASE your_database_name
#### Make your migrations python3 manage.py makemigrations or python3 manage.py makameigrations accounts_user
#### Apply your migrations: python3 manage.py migrate
#### Fire up your app: Check the urls to get supported urls
#### You may use your preferred API platform like Postman to interact with the functionalities


#### You may also comment this line  'DEFAULT_RENDERER_CLASSES':('rest_framework.renderers.JSONRenderer',) in your settings.py, to use the default Django Rest Framework renderer

